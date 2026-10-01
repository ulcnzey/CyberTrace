"""Live capture control."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.config import settings
from app.core.errors import AnalysisError
from app.ingestion.live_source import list_interfaces, unavailable_reason
from app.services.live_monitor import live_monitor

router = APIRouter(prefix="/api", tags=["live"])


class LiveStartRequest(BaseModel):
    interface: str = Field(min_length=1, max_length=255)
    duration_seconds: int | None = None


@router.get("/settings")
def get_settings() -> dict:
    reason = unavailable_reason()
    return {
        "notice": (
            "CyberTrace analyzes traffic you are allowed to capture. "
            "Uploaded packet files are deleted after analysis. "
            "Results stored here are summaries, detections, and indicators."
        ),
        "max_upload_bytes": settings.max_upload_bytes,
        "max_packets": settings.max_packets,
        "live_max_packets": settings.live_max_packets,
        "live_default_duration": settings.live_default_duration,
        "live_max_duration": settings.live_max_duration,
        "capture_available": reason is None,
        "capture_message": reason or "Live capture is available on this host.",
    }


@router.get("/interfaces")
def get_interfaces() -> dict:
    reason = unavailable_reason()
    return {
        "available": reason is None,
        "message": reason or "Select an interface to start an authorized capture.",
        "interfaces": list_interfaces(),
    }


@router.get("/live/status")
def live_status() -> dict:
    return live_monitor.status()


@router.post("/live/start", status_code=201)
def live_start(body: LiveStartRequest) -> dict:
    try:
        return live_monitor.start(body.interface, body.duration_seconds)
    except AnalysisError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc


@router.post("/live/stop")
def live_stop() -> dict:
    return live_monitor.stop()
