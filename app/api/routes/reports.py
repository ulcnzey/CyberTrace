"""JSON and PDF report downloads."""

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app.core.errors import AnalysisError
from app.reporting.reports import json_report_path, pdf_report_path

router = APIRouter(prefix="/api", tags=["reports"])


@router.get("/analyses/{session_id}/reports/json")
def download_json(session_id: int) -> FileResponse:
    path = _build(json_report_path, session_id)
    return FileResponse(path, media_type="application/json", filename=path.name)


@router.get("/analyses/{session_id}/reports/pdf")
def download_pdf(session_id: int) -> FileResponse:
    path = _build(pdf_report_path, session_id)
    return FileResponse(path, media_type="application/pdf", filename=path.name)


def _build(builder, session_id: int):
    try:
        return builder(session_id)
    except AnalysisError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
