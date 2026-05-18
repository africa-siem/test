"""
SIEM Africa - Agent (Module 3) - Package watchers
Surveille les sources d'alertes (Wazuh, et via Wazuh : Snort, Apache, sshd, etc.)
"""
from watchers.parser import parse_wazuh_event, level_to_severity, _level_to_severity
from watchers.wazuh import WazuhWatcher

__all__ = ["WazuhWatcher", "parse_wazuh_event", "level_to_severity", "_level_to_severity"]
