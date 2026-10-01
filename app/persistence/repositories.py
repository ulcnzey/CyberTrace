"""Write pipeline results into SQLite."""

import json

from sqlalchemy import delete

from app.core.clock import from_timestamp
from app.core.domain import PipelineResult
from app.core.pipeline import utcnow
from app.persistence.database import SessionLocal
from app.persistence.orm import (
    Alert,
    AnalysisSession,
    Finding,
    FlowSummary,
    Indicator,
    ProtocolEvent,
    TimelineEvent,
)


def create_session(*, name: str, source_type: str, source_label: str) -> int:
    db = SessionLocal()
    try:
        row = AnalysisSession(
            name=name[:255],
            source_type=source_type,
            source_label=source_label[:255],
            status="running",
            started_at=utcnow(),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row.id
    finally:
        db.close()


def mark_session(
    session_id: int,
    *,
    status: str,
    error_message: str | None = None,
    warning: str | None = None,
) -> None:
    db = SessionLocal()
    try:
        row = db.get(AnalysisSession, session_id)
        if row is None:
            return
        row.status = status
        row.error_message = error_message
        if warning is not None:
            row.warning = warning
        row.ended_at = utcnow()
        db.commit()
    finally:
        db.close()


def save_result(session_id: int, result: PipelineResult, *, status: str) -> None:
    db = SessionLocal()
    try:
        row = db.get(AnalysisSession, session_id)
        if row is None:
            return
        _clear_results(db, session_id)
        alert_ids = _insert_alerts(db, session_id, result)
        _insert_flows(db, session_id, result)
        _insert_protocol_events(db, session_id, result)
        _insert_findings(db, session_id, result, alert_ids)
        _insert_indicators(db, session_id, result, alert_ids)
        _insert_timeline(db, session_id, result, alert_ids)
        row.status = status
        row.packet_count = result.packet_count
        row.byte_count = result.byte_count
        row.protocol_counts = json.dumps(result.protocol_counts)
        row.traffic_buckets = json.dumps(result.traffic_buckets)
        row.warning = result.warning
        row.error_message = None
        if status in {"completed", "stopped", "failed"}:
            row.ended_at = utcnow()
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _clear_results(db, session_id: int) -> None:
    for model in (Finding, Indicator, TimelineEvent, ProtocolEvent, FlowSummary, Alert):
        db.execute(delete(model).where(model.session_id == session_id))


def _insert_alerts(db, session_id: int, result: PipelineResult) -> dict[str, int]:
    mapping: dict[str, int] = {}
    for alert in result.alerts:
        row = Alert(
            session_id=session_id,
            detector_id=alert.detector_id,
            severity=alert.severity,
            confidence=alert.confidence,
            title=alert.name[:255],
            src_ip=alert.src_ip,
            dst_ip=alert.dst_ip,
            src_port=alert.src_port,
            dst_port=alert.dst_port,
            protocol=alert.protocol,
            observed_at=from_timestamp(alert.timestamp),
            evidence=alert.evidence,
            recommended_action=alert.recommended_action,
            summary=alert.evidence,
        )
        db.add(row)
        db.flush()
        mapping[alert.key] = row.id
    return mapping


def _insert_flows(db, session_id: int, result: PipelineResult) -> None:
    for flow in result.flows:
        db.add(
            FlowSummary(
                session_id=session_id,
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                src_port=flow.src_port,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                src_mac=flow.src_mac,
                dst_mac=flow.dst_mac,
                packet_count=flow.packet_count,
                byte_count=flow.byte_count,
                syn_count=flow.syn_count,
                ack_count=flow.ack_count,
                started_at=from_timestamp(flow.started_at),
                ended_at=from_timestamp(flow.ended_at),
            )
        )


def _insert_protocol_events(db, session_id: int, result: PipelineResult) -> None:
    for event in result.protocol_events[:150]:
        db.add(
            ProtocolEvent(
                session_id=session_id,
                event_type=event.event_type,
                observed_at=from_timestamp(event.timestamp),
                summary=event.summary,
            )
        )


def _insert_findings(db, session_id: int, result: PipelineResult, alert_ids: dict[str, int]) -> None:
    key_by_finding = {}
    for alert in result.alerts:
        for finding in alert.findings:
            key_by_finding[id(finding)] = alert.key
    for finding in result.findings:
        db.add(
            Finding(
                session_id=session_id,
                alert_id=alert_ids.get(key_by_finding.get(id(finding), "")),
                detector_id=finding.detector_id,
                name=finding.name[:255],
                confidence=finding.confidence,
                severity=finding.severity or "low",
                src_ip=finding.src_ip,
                dst_ip=finding.dst_ip,
                src_port=finding.src_port,
                dst_port=finding.dst_port,
                protocol=finding.protocol,
                observed_at=from_timestamp(finding.timestamp),
                evidence=finding.evidence,
                recommended_action=finding.recommended_action,
                summary=finding.evidence,
            )
        )


def _insert_indicators(db, session_id: int, result: PipelineResult, alert_ids: dict[str, int]) -> None:
    for indicator in result.indicators:
        db.add(
            Indicator(
                session_id=session_id,
                alert_id=alert_ids.get(indicator.alert_key or ""),
                indicator_type=indicator.indicator_type,
                value=indicator.value,
                observed_at=from_timestamp(indicator.timestamp),
            )
        )


def _insert_timeline(db, session_id: int, result: PipelineResult, alert_ids: dict[str, int]) -> None:
    for item in result.timeline:
        db.add(
            TimelineEvent(
                session_id=session_id,
                alert_id=alert_ids.get(item.alert_key or ""),
                occurred_at=from_timestamp(item.timestamp),
                event_type=item.event_type,
                severity=item.severity,
                summary=item.summary,
            )
        )
