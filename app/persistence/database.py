"""SQLite engine and session management."""

from collections.abc import Generator

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings
from app.persistence.orm import Base

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

_FINDING_COLUMNS = {"confidence", "severity", "evidence", "detector_id"}


@event.listens_for(engine, "connect")
def _configure_sqlite(dbapi_connection, _connection_record) -> None:
    if engine.dialect.name != "sqlite":
        return
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def _schema_is_current() -> bool:
    tables = set(inspect(engine).get_table_names())
    if "findings" not in tables:
        return True
    columns = {column["name"] for column in inspect(engine).get_columns("findings")}
    return _FINDING_COLUMNS <= columns


def init_db() -> None:
    """Create tables. Recreate them when an older Phase 0 schema is present."""
    if not _schema_is_current():
        Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
