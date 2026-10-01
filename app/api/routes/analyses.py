"""Analysis, flow, host, alert, indicator, and timeline routes."""

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.config import settings
from app.core.errors import AnalysisError
from app.services import analysis_service
from app.services.read_models import (
    analysis_detail,
    list_alerts,
    list_analyses,
    list_flows,
    list_hosts,
    list_iocs,
    list_timeline,
    overview,
)

router = APIRouter(prefix="/api", tags=["analysis"])


@router.get("/overview")
def get_overview(session_id: int | None = None) -> dict:
    if session_id is not None and analysis_detail(session_id) is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return overview(session_id)


@router.get("/analyses")
def get_analyses() -> dict:
    return list_analyses()


@router.post("/analyses/pcap", status_code=201)
def upload_pcap(file: UploadFile = File(...)) -> dict:
    data = file.file.read(settings.max_upload_bytes + 1)
    try:
        return analysis_service.analyze_upload(file.filename or "capture.pcap", data)
    except AnalysisError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc


@router.get("/analyses/{session_id}")
def get_analysis(session_id: int) -> dict:
    detail = analysis_detail(session_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return detail


@router.get("/analyses/{session_id}/flows")
def get_flows(session_id: int) -> dict:
    return _require(list_flows(session_id))


@router.get("/analyses/{session_id}/hosts")
def get_hosts(session_id: int) -> dict:
    return _require(list_hosts(session_id))


@router.get("/analyses/{session_id}/alerts")
def get_alerts(session_id: int) -> dict:
    return _require(list_alerts(session_id))


@router.get("/alerts")
def get_all_alerts() -> dict:
    return list_alerts() or {"items": []}


@router.get("/analyses/{session_id}/iocs")
def get_iocs(session_id: int) -> dict:
    return _require(list_iocs(session_id))


@router.get("/analyses/{session_id}/timeline")
def get_timeline(session_id: int) -> dict:
    return _require(list_timeline(session_id))


def _require(payload: dict | None) -> dict:
    if payload is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return payload
