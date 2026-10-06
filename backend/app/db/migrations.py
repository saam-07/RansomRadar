"""
Simple versioned migrations for AdaptShield SQLite database.
"""

from __future__ import annotations

import logging
from sqlalchemy.orm import Session
from backend.app.db.session import engine, Base, SessionLocal
from backend.app.db.models import SchemaVersion

logger = logging.getLogger(__name__)

CURRENT_DB_VERSION = 1
MIGRATION_DESCRIPTIONS = {
    1: "Initial schema: schema_version, scenario_runs, alerts, containment_actions, training_jobs",
}


def init_db() -> None:
    """
    Initializes tables and applies versioned migrations.
    """
    # 1. Create tables if they don't exist
    Base.metadata.create_all(bind=engine)

    # 2. Check and record schema version
    db: Session = SessionLocal()
    try:
        current_entry = db.query(SchemaVersion).order_by(SchemaVersion.version.desc()).first()
        installed_version = current_entry.version if current_entry else 0

        if installed_version < CURRENT_DB_VERSION:
            for v in range(installed_version + 1, CURRENT_DB_VERSION + 1):
                desc = MIGRATION_DESCRIPTIONS.get(v, f"Migration version {v}")
                new_version = SchemaVersion(version=v, description=desc)
                db.add(new_version)
                logger.info(f"Applied database migration v{v}: {desc}")
            db.commit()
    except Exception as e:
        logger.error(f"Error checking/applying migrations: {e}")
        db.rollback()
    finally:
        db.close()
