"""
SIEM Africa - Agent (Module 3) - processor/utils.py
Utilitaires pour le processor.
"""
import ipaddress


def is_private_ip(ip_str):
    """Détermine si une IP est privée/loopback/link-local/multicast.
    Utilisé pour ne JAMAIS bloquer ces IPs (anti-loopback)."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except (ValueError, TypeError):
        return False
