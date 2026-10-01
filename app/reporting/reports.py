"""JSON and PDF reports built from stored analysis results."""

import json
from pathlib import Path

from app.config import settings
from app.core.errors import AnalysisError
from app.persistence.database import SessionLocal
from app.persistence.orm import Report
from app.services.read_models import report_document


def json_report_path(session_id: int) -> Path:
    document = _document(session_id)
    path = settings.report_dir / f"session-{session_id}.json"
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    _remember(session_id, "json", path)
    return path


def pdf_report_path(session_id: int) -> Path:
    document = _document(session_id)
    path = settings.report_dir / f"session-{session_id}.pdf"
    _write_pdf(path, document)
    _remember(session_id, "pdf", path)
    return path


def _document(session_id: int) -> dict:
    document = report_document(session_id)
    if document is None:
        raise AnalysisError("Analysis not found.", status_code=404)
    if document["summary"]["status"] == "running":
        raise AnalysisError("The analysis is still running.", status_code=409)
    return document


def _remember(session_id: int, report_format: str, path: Path) -> None:
    db = SessionLocal()
    try:
        from sqlalchemy import select

        row = db.scalar(
            select(Report).where(
                Report.session_id == session_id,
                Report.report_format == report_format,
            )
        )
        if row is None:
            db.add(
                Report(
                    session_id=session_id,
                    report_format=report_format,
                    location=str(path),
                )
            )
        else:
            row.location = str(path)
        db.commit()
    finally:
        db.close()


def _write_pdf(path: Path, document: dict) -> None:
    from fpdf import FPDF

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(15, 15, 15)
    pdf.add_page()
    _heading(pdf, "CyberTrace analysis report", 18)
    summary = document["summary"]
    _text(pdf, document["notice"])
    _text(pdf, f"Analysis: {summary['name']} ({summary['source_type']})")
    _text(pdf, f"Status: {summary['status']}")
    _heading(pdf, "Summary", 14)
    _text(
        pdf,
        (
            f"Packets: {summary['packet_count']}    "
            f"Bytes: {summary['byte_count']}    "
            f"Connections: {summary['flow_count']}    "
            f"Alerts: {summary['alert_count']}"
        ),
    )
    protocols = document["traffic_statistics"]["protocols"]
    if protocols:
        _text(pdf, "Protocols: " + ", ".join(f"{name} {count}" for name, count in protocols.items()))
    _heading(pdf, "Hosts", 14)
    for host in document["hosts"][:30]:
        macs = ", ".join(host["macs"]) or "no MAC"
        _text(pdf, f"{host['ip']} ({host['role']}) sent {host['bytes_sent']} bytes; {macs}")
    if not document["hosts"]:
        _text(pdf, "No hosts were observed.")
    _heading(pdf, "Connections", 14)
    for flow in document["connections"][:40]:
        _text(
            pdf,
            (
                f"{flow['protocol']} {flow['src_ip']}:{flow['src_port']} -> "
                f"{flow['dst_ip']}:{flow['dst_port']} "
                f"({flow['packet_count']} packets, {flow['byte_count']} bytes)"
            ),
        )
    if not document["connections"]:
        _text(pdf, "No connections were stored.")
    _heading(pdf, "Alerts", 14)
    for alert in document["alerts"][:40]:
        _text(
            pdf,
            (
                f"[{alert['severity']}] {alert['name']} "
                f"(confidence {alert['confidence']})"
            ),
        )
        _text(pdf, alert["evidence"])
        _text(pdf, f"Action: {alert['recommended_action']}")
    if not document["alerts"]:
        _text(pdf, "No alerts.")
    _heading(pdf, "Indicators", 14)
    for indicator in document["iocs"][:60]:
        _text(pdf, f"{indicator['indicator_type']}: {indicator['value']}")
    if not document["iocs"]:
        _text(pdf, "No indicators.")
    _heading(pdf, "Timeline", 14)
    for event in document["timeline"][:60]:
        _text(pdf, f"{event['occurred_at'] or ''}  {event['summary']}")
    pdf.output(str(path))


def _text(pdf, text: str) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", size=11)
    pdf.multi_cell(pdf.epw, 6, _safe(text))


def _heading(pdf, text: str, size: int) -> None:
    pdf.ln(2)
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", size)
    pdf.multi_cell(pdf.epw, 8, _safe(text))


def _safe(text: str) -> str:
    return str(text).encode("latin-1", errors="replace").decode("latin-1")
