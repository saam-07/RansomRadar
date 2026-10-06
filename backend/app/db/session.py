"""
Database session management using SQLAlchemy and SQLite.
"""

from __future__ import annotations

from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from backend.app.config import settings

db_url = settings.database.url
# Ensure data directory exists if local sqlite path
if db_url.startswith("sqlite:///"):
    path_str = db_url.replace("sqlite:///", "")
    db_path = Path(path_str)
    db_path.parent.mkdir(parents=True, exist_ok=True)

# check_same_thread=False allows FastAPI multi-threaded requests with SQLite
engine = create_engine(
    db_url,
    connect_args={"check_same_thread": False} if "sqlite" in db_url else {},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency for database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
