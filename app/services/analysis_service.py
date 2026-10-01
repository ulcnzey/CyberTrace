"""Run a capture through the shared pipeline and store the result."""

import logging
from pathlib import Path
from uuid import uuid4

from app.config import settings
from app.core.domain import NormalizedPacket
from app.core.errors import AnalysisError
from app.core.pipeline import run_pipeline, utcnow
from app.ingestion.pcap_source import load_capture, looks_like_capture
from app.persistence.repositories import create_session, mark_session, save_result
from app.services.read_models import analysis_detail

logger = logging.getLogger(__name__)


def analyze_upload(filename: str, data: bytes) -> dict:
    safe_name = Path(filename or "capture.pcap").name
    lowered = safe_name.lower()
    if not lowered.endswith((".pcap", ".pcapng")):
        raise AnalysisError("Upload a .pcap or .pcapng file.")
    if len(data) > settings.max_upload_bytes:
        raise AnalysisError("The file exceeds the upload limit.")
    if not looks_like_capture(data):
        raise AnalysisError("The file is not a PCAP or PCAPNG capture.")
    path = settings.upload_dir / f"{uuid4().hex}_{safe_name}"
    path.write_bytes(data)
    try:
        return analyze_capture_file(path, safe_name)
    finally:
        path.unlink(missing_ok=True)


def analyze_capture_file(path: Path, original_name: str) -> dict:
    packets, warning = load_capture(path)
    if not packets:
        raise AnalysisError("The capture contains no readable packets.")
    return analyze_packets(
        packets,
        name=original_name,
        source_type="pcap",
        source_label=original_name,
        warning=warning,
    )


def analyze_packets(
    packets: list[NormalizedPacket],
    *,
    name: str,
    source_type: str,
    source_label: str,
    warning: str | None = None,
    status: str = "completed",
) -> dict:
    session_id = create_session(name=name, source_type=source_type, source_label=source_label)
    try:
        started = utcnow()
        result = run_pipeline(
            packets,
            started_at=started,
            ended_at=utcnow(),
            source_label=source_label,
            warning=warning,
        )
        save_result(session_id, result, status=status)
    except AnalysisError as exc:
        mark_session(session_id, status="failed", error_message=exc.message)
        raise
    except Exception as exc:
        logger.exception("analysis failed")
        mark_session(session_id, status="failed", error_message="The capture could not be analyzed.")
        raise AnalysisError("The capture could not be analyzed.") from exc
    detail = analysis_detail(session_id)
    if detail is None:
        raise AnalysisError("The analysis could not be stored.")
    return detail
