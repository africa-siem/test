"""
SIEM Africa - Agent (Module 3) - Package processor
Cœur de l'agent : transforme les events bruts en alertes structurées.
"""
from processor.alert_processor import AlertProcessor
from processor.utils import is_private_ip

__all__ = ["AlertProcessor", "is_private_ip"]
