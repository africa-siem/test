"""
SIEM Africa - Agent (Module 3) - response/ip_blocker.py
IPBlocker : gestion bloquage/déblocage IP via iptables.
Inclut whitelist (via alert_filters IGNORE) et anti-loopback.
"""
import logging

from db import get_db
from response.utils import is_blockable_ip
import response.utils as _utils  # pour permettre le mock de run_iptables dans tests

logger = logging.getLogger(__name__)


def _run(args):
    """Wrapper pour permettre le mocking de run_iptables dans les tests."""
    return _utils.run_iptables(args)


# ============================================================================
class IPBlocker:
    """Gère le blocage et déblocage d'IPs via iptables."""

    def __init__(self):
        self.db = get_db()

    def is_whitelisted(self, ip_address):
        """Vérifie si l'IP est en whitelist (filtre IGNORE actif)."""
        try:
            with self.db.cursor() as cur:
                cur.execute("""
                    SELECT id FROM alert_filters
                    WHERE is_active = 1 AND action = 'IGNORE'
                    AND src_ip IS NOT NULL
                    AND (src_ip = ? OR ? LIKE src_ip || '%')
                    LIMIT 1
                """, (ip_address, ip_address))
                return cur.fetchone() is not None
        except Exception as e:
            logger.error(f"Erreur whitelist check : {e}")
            return False

    def block_ip(self, ip_address, reason, alert_id=None, duration_minutes=1440):
        """
        Bloque une IP via iptables + BDD.
        Retourne (success: bool, message: str).
        """
        # 1. Vérification anti-loopback
        if not is_blockable_ip(ip_address):
            return False, f"IP non bloquable (privée/loopback) : {ip_address}"

        # 2. Vérification whitelist
        if self.is_whitelisted(ip_address):
            logger.info(f"IP {ip_address} en whitelist, blocage refusé")
            self.db.insert_audit("ip_block_skipped_whitelist",
                                 resource_type="ip", resource_id=ip_address,
                                 details={"reason": "whitelist", "alert_id": alert_id})
            return False, f"IP en whitelist : {ip_address}"

        # 3. Déjà bloquée ?
        if self.db.is_ip_blocked(ip_address):
            return False, f"IP déjà bloquée : {ip_address}"

        # 4. iptables
        success, err = _run(["-I", "INPUT", "-s", ip_address, "-j", "DROP"])
        if not success:
            logger.error(f"iptables échec pour {ip_address} : {err}")
            return False, f"iptables : {err}"

        # 5. INSERT en BDD
        block_id = self.db.insert_blocked_ip(
            ip_address=ip_address,
            reason=reason,
            duration_minutes=duration_minutes,
            alert_id=alert_id,
        )

        if not block_id:
            # Rollback iptables
            _run(["-D", "INPUT", "-s", ip_address, "-j", "DROP"])
            return False, "Échec INSERT blocked_ips, blocage annulé"

        # 6. Audit
        self.db.insert_audit("ip_block",
                             resource_type="ip", resource_id=ip_address,
                             details={"block_id": block_id, "duration_min": duration_minutes,
                                      "reason": reason[:200]})

        logger.warning(f"IP {ip_address} BLOQUÉE ({duration_minutes}min) - {reason[:80]}")
        return True, f"IP {ip_address} bloquée pour {duration_minutes}min"

    def unblock_ip(self, ip_address, block_id):
        """Débloque une IP (cron expiration ou manuel)."""
        # iptables -D
        success, err = _run(["-D", "INPUT", "-s", ip_address, "-j", "DROP"])
        if not success:
            # Peut arriver si déjà supprimé manuellement
            logger.warning(f"iptables -D échec pour {ip_address} : {err}")

        # Mark inactive
        self.db.mark_block_inactive(block_id)

        self.db.insert_audit("ip_unblock",
                             resource_type="ip", resource_id=ip_address,
                             details={"block_id": block_id})

        logger.info(f"IP {ip_address} débloquée (expiration)")


# ============================================================================
# WORKER BLOCK (thread qui consomme la queue)
