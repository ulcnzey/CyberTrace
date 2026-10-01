"""Runtime configuration for CyberTrace."""

import os
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

AUTHORIZED_NOTICE = (
    "CyberTrace is for authorized and educational network analysis only. "
    "It does not inject packets, exploit hosts, or collect credentials."
)


@dataclass(frozen=True)
class Settings:
    app_name: str
    app_version: str
    project_root: Path
    data_dir: Path
    web_dir: Path
    upload_dir: Path
    report_dir: Path
    database_url: str
    max_upload_bytes: int
    max_packets: int
    live_max_packets: int
    live_default_duration: int
    live_max_duration: int
    large_outbound_bytes: int


def _positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def load_settings() -> Settings:
    """Load settings from the environment, with local defaults."""
    from app import __version__

    data_dir = Path(os.environ.get("CYBERTRACE_DATA_DIR", PROJECT_ROOT / "data"))
    upload_dir = data_dir / "uploads"
    report_dir = data_dir / "reports"
    data_dir.mkdir(parents=True, exist_ok=True)
    upload_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    database_path = data_dir / "cybertrace.db"
    database_url = os.environ.get(
        "CYBERTRACE_DATABASE_URL",
        f"sqlite:///{database_path.as_posix()}",
    )

    return Settings(
        app_name=os.environ.get("CYBERTRACE_APP_NAME", "CyberTrace"),
        app_version=__version__,
        project_root=PROJECT_ROOT,
        data_dir=data_dir,
        web_dir=PROJECT_ROOT / "web",
        upload_dir=upload_dir,
        report_dir=report_dir,
        database_url=database_url,
        max_upload_bytes=_positive_int("CYBERTRACE_MAX_UPLOAD_BYTES", 50 * 1024 * 1024),
        max_packets=_positive_int("CYBERTRACE_MAX_PACKETS", 100_000),
        live_max_packets=_positive_int("CYBERTRACE_LIVE_MAX_PACKETS", 20_000),
        live_default_duration=_positive_int("CYBERTRACE_LIVE_DEFAULT_DURATION", 60),
        live_max_duration=_positive_int("CYBERTRACE_LIVE_MAX_DURATION", 300),
        large_outbound_bytes=_positive_int("CYBERTRACE_LARGE_OUTBOUND_BYTES", 100_000),
    )


settings = load_settings()
