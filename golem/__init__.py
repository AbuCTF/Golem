"""Golem — agent-driven Android emulation and instrumentation harness."""

__version__ = "0.5.0"

from golem.pool import Pool
from golem.session import Session
from golem.frida_bridge import FridaBridge
from golem.context import ContextTracker, HealthMonitor
from golem.evidence import EvidenceStore
from golem.multi import SessionGroup

__all__ = [
    "Pool", "Session", "FridaBridge",
    "ContextTracker", "HealthMonitor", "EvidenceStore",
    "SessionGroup",
]
