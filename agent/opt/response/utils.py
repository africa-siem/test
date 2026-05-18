"""
SIEM Africa - Agent (Module 3) - response/utils.py
Utilitaires pour l'Active Response.
"""
import subprocess
import ipaddress


def is_blockable_ip(ip_str):
    """Vérifie si une IP peut être bloquée (refuse privées/loopback/link-local/multicast).
    SÉCURITÉ : empêche de bloquer accidentellement le LAN ou des IPs réservées."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return False
        return True
    except (ValueError, TypeError):
        return False


def run_iptables(args):
    """
    Exécute une commande iptables via sudo.
    Retourne (success: bool, stderr: str ou None).
    Le sudoers doit autoriser siem-agent à exécuter iptables sans password.
    """
    cmd = ["sudo", "-n", "iptables"] + args
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return True, None
        return False, result.stderr.strip()
    except FileNotFoundError:
        return False, "iptables ou sudo introuvable"
    except subprocess.TimeoutExpired:
        return False, "iptables timeout"
    except Exception as e:
        return False, str(e)
