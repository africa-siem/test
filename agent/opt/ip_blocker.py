"""SIEM Africa - Agent : Blocage d'IP via iptables.

Active uniquement si settings.ip_block_enabled = true.
Necessite que l'agent ait les droits CAP_NET_ADMIN ou tourne sous sudo.
"""
import ipaddress
import subprocess

import db
from logger import setup_logger


log = setup_logger("ip_blocker")


def _is_valid_public_ip(ip_str):
    """Refuse les IP privees / loopback / 0.0.0.0 pour eviter de se bloquer soi-meme."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
            return False
        return True
    except ValueError:
        return False


def is_already_blocked(ip):
    """Verifie si l'IP est deja blacklistee en BDD."""
    try:
        conn = db._get_conn()
        row = conn.execute(
            "SELECT 1 FROM ip_blocklist WHERE ip_address=? AND is_active=1",
            (ip,),
        ).fetchone()
        return row is not None
    except Exception:  # noqa: BLE001
        return False


def block_ip(ip, reason="auto-blocked by agent"):
    """Ajoute une regle iptables DROP + insere en BDD."""
    if not _is_valid_public_ip(ip):
        log.warning(f"IP {ip} invalide ou privee - blocage refuse")
        return False

    if is_already_blocked(ip):
        log.debug(f"IP {ip} deja bloquee")
        return True

    try:
        result = subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            log.error(f"iptables echec pour {ip} : {result.stderr.strip()}")
            return False
    except (subprocess.SubprocessError, FileNotFoundError) as exc:
        log.error(f"iptables non disponible : {exc}")
        return False

    try:
        conn = db._get_conn()
        conn.execute(
            """
            INSERT INTO ip_blocklist (ip_address, reason, blocked_by, is_active, created_at)
            VALUES (?, ?, 'agent-auto', 1, CURRENT_TIMESTAMP)
            """,
            (ip, reason),
        )
        log.info(f"IP {ip} bloquee : {reason}")
        return True
    except Exception as exc:  # noqa: BLE001
        log.error(f"Insert ip_blocklist echec : {exc}")
        return False
