"""
Database package for AdaptShield backend.
"""

from backend.app.db.session import engine, SessionLocal, Base, get_db
from backend.app.db.models import (
    SchemaVersion,
    ScenarioRunRecord,
    AlertRecord,
    ContainmentRecord,
    TrainingJobRecord,
)
from backend.app.db.migrations import init_db
from backend.app.db.seed import seed_demo_data

__all__ = [
    "engine",
    "SessionLocal",
    "Base",
    "get_db",
    "SchemaVersion",
    "ScenarioRunRecord",
    "AlertRecord",
    "ContainmentRecord",
    "TrainingJobRecord",
    "init_db",
    "seed_demo_data",
]
