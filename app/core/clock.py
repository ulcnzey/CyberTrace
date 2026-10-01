"""Small datetime helpers used by the pipeline and the API."""

from datetime import datetime, timezone


def from_timestamp(value: float | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromtimestamp(float(value), tz=timezone.utc)


def ensure_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def isoformat(value: datetime | None) -> str | None:
    normalized = ensure_utc(value)
    if normalized is None:
        return None
    return normalized.isoformat()
