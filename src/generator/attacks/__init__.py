"""Учебные сценарии атак, ограниченные безопасными запросами."""

from .brute_force import run_brute_force
from .mass_read import run_mass_read
from .privilege_escalation import run_privilege_escalation
from .sql_injection import run_sql_injection
from .suspicious_delete import run_suspicious_delete
from .new_ip_login import run_new_ip_login

__all__ = [
    "run_brute_force",
    "run_mass_read",
    "run_privilege_escalation",
    "run_sql_injection",
    "run_suspicious_delete",
    "run_new_ip_login",
]
