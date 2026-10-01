"""Read stored analysis results for the API and reports."""

import json
from collections import Counter

import ipaddress
from sqlalchemy import func, select

from app.config import AUTHORIZED_NOTICE
from app.core.clock import isoformat
from app.persistence.database import SessionLocal
from app.persistence.orm import (
    Alert,
    AnalysisSession,
    FlowSummary,
    Indicator,
    TimelineEvent,
)

_FLOW_LIMIT = 300
_LIST_LIMIT = 50


def list_analyses() -> dict:
    db = SessionLocal()
    try:
        rows = db.scalars(
            select(AnalysisSession).order_by(AnalysisSession.id.desc()).limit(_LIST_LIMIT)
        ).all()
        return {"items": [_session_summary(row, db) for row in rows]}
    finally:
        db.close()


def analysis_detail(session_id: int) -> dict | None:
    db = SessionLocal()
    try:
        row = db.get(AnalysisSession, session_id)
        if row is None:
            return None
        return _session_detail(row, db)
    finally:
        db.close()


def list_flows(session_id: int) -> dict | None:
    db = SessionLocal()
    try:
        if db.get(AnalysisSession, session_id) is None:
            return None
        total = db.scalar(
            select(func.count()).select_from(FlowSummary).where(FlowSummary.session_id == session_id)
        )
        rows = db.scalars(
            select(FlowSummary)
            .where(FlowSummary.session_id == session_id)
            .order_by(FlowSummary.byte_count.desc())
            .limit(_FLOW_LIMIT)
        ).all()
        return {
            "total": int(total or 0),
            "truncated": int(total or 0) > len(rows),
            "items": [_flow(row) for row in rows],
        }
    finally:
        db.close()


def list_hosts(session_id: int) -> dict | None:
    db = SessionLocal()
    try:
        if db.get(AnalysisSession, session_id) is None:
            return None
        rows = db.scalars(select(FlowSummary).where(FlowSummary.session_id == session_id)).all()
        return {"items": _hosts(rows)}
    finally:
        db.close()


def list_alerts(session_id: int | None = None) -> dict | None:
    db = SessionLocal()
    try:
        query = select(Alert).order_by(Alert.id.desc())
        if session_id is not None:
            if db.get(AnalysisSession, session_id) is None:
                return None
            query = query.where(Alert.session_id == session_id)
        rows = db.scalars(query.limit(200)).all()
        return {"items": [_alert(row) for row in rows]}
    finally:
        db.close()


def list_iocs(session_id: int) -> dict | None:
    db = SessionLocal()
    try:
        if db.get(AnalysisSession, session_id) is None:
            return None
        rows = db.scalars(
            select(Indicator).where(Indicator.session_id == session_id).order_by(Indicator.id)
        ).all()
        return {"items": [_indicator(row) for row in rows]}
    finally:
        db.close()


def list_timeline(session_id: int) -> dict | None:
    db = SessionLocal()
    try:
        if db.get(AnalysisSession, session_id) is None:
            return None
        rows = db.scalars(
            select(TimelineEvent)
            .where(TimelineEvent.session_id == session_id)
            .order_by(TimelineEvent.id)
        ).all()
        rows = sorted(rows, key=_timeline_key)
        return {"items": [_timeline(row) for row in rows]}
    finally:
        db.close()


def overview(session_id: int | None = None) -> dict:
    db = SessionLocal()
    try:
        analyses = int(db.scalar(select(func.count()).select_from(AnalysisSession)) or 0)
        packets = int(db.scalar(select(func.coalesce(func.sum(AnalysisSession.packet_count), 0))) or 0)
        alerts = int(db.scalar(select(func.count()).select_from(Alert)) or 0)
        row = None
        if session_id is not None:
            row = db.get(AnalysisSession, session_id)
        if row is None:
            row = db.scalar(select(AnalysisSession).order_by(AnalysisSession.id.desc()).limit(1))
        detail = _session_detail(row, db) if row is not None else None
        severity = Counter()
        recent = []
        topology = {"nodes": [], "links": []}
        stats = {"packets": 0, "connections": 0, "hosts": 0, "alerts": 0}
        traffic = []
        protocols = {}
        if row is not None and detail is not None:
            alert_rows = db.scalars(select(Alert).where(Alert.session_id == row.id)).all()
            for alert in alert_rows:
                severity[alert.severity] += 1
            flow_rows = db.scalars(select(FlowSummary).where(FlowSummary.session_id == row.id)).all()
            hosts = _hosts(flow_rows)
            stats = {
                "packets": detail["packet_count"],
                "connections": len(flow_rows),
                "hosts": len(hosts),
                "alerts": len(alert_rows),
            }
            traffic = detail["traffic"]
            protocols = detail["protocol_counts"]
            events = db.scalars(
                select(TimelineEvent)
                .where(TimelineEvent.session_id == row.id)
                .order_by(TimelineEvent.occurred_at.desc(), TimelineEvent.id.desc())
                .limit(8)
            ).all()
            recent = [_timeline(event) for event in events]
            topology = _topology(flow_rows)
        return {
            "notice": AUTHORIZED_NOTICE,
            "totals": {"analyses": analyses, "packets": packets, "alerts": alerts},
            "session": detail,
            "stats": stats,
            "severity": {name: severity.get(name, 0) for name in ("critical", "high", "medium", "low", "info")},
            "traffic": traffic,
            "protocols": protocols,
            "recent_events": recent,
            "topology": topology,
        }
    finally:
        db.close()


def report_document(session_id: int) -> dict | None:
    detail = analysis_detail(session_id)
    if detail is None:
        return None
    flows = list_flows(session_id) or {"items": [], "total": 0}
    hosts = list_hosts(session_id) or {"items": []}
    alerts = list_alerts(session_id)
    iocs = list_iocs(session_id) or {"items": []}
    timeline = list_timeline(session_id) or {"items": []}
    return {
        "application": "CyberTrace",
        "notice": AUTHORIZED_NOTICE,
        "summary": detail,
        "traffic_statistics": {
            "packet_count": detail["packet_count"],
            "byte_count": detail["byte_count"],
            "protocols": detail["protocol_counts"],
            "buckets": detail["traffic"],
        },
        "hosts": hosts["items"],
        "connections": flows["items"],
        "connection_total": flows["total"],
        "alerts": alerts["items"],
        "iocs": iocs["items"],
        "timeline": timeline["items"],
    }


def _session_summary(row: AnalysisSession, db) -> dict:
    alert_count = int(
        db.scalar(select(func.count()).select_from(Alert).where(Alert.session_id == row.id)) or 0
    )
    return {
        "id": row.id,
        "name": row.name,
        "source_type": row.source_type,
        "source_label": row.source_label,
        "status": row.status,
        "packet_count": row.packet_count,
        "alert_count": alert_count,
        "created_at": isoformat(row.created_at),
        "warning": row.warning,
        "error_message": row.error_message,
    }


def _session_detail(row: AnalysisSession, db) -> dict:
    summary = _session_summary(row, db)
    flow_count = int(
        db.scalar(
            select(func.count()).select_from(FlowSummary).where(FlowSummary.session_id == row.id)
        )
        or 0
    )
    summary.update(
        {
            "byte_count": row.byte_count,
            "started_at": isoformat(row.started_at),
            "ended_at": isoformat(row.ended_at),
            "protocol_counts": _loads(row.protocol_counts, {}),
            "traffic": _loads(row.traffic_buckets, []),
            "flow_count": flow_count,
        }
    )
    return summary


def _flow(row: FlowSummary) -> dict:
    return {
        "src_ip": row.src_ip,
        "dst_ip": row.dst_ip,
        "src_port": row.src_port,
        "dst_port": row.dst_port,
        "protocol": row.protocol,
        "src_mac": row.src_mac,
        "dst_mac": row.dst_mac,
        "packet_count": row.packet_count,
        "byte_count": row.byte_count,
        "started_at": isoformat(row.started_at),
        "ended_at": isoformat(row.ended_at),
    }


def _alert(row: Alert) -> dict:
    return {
        "id": row.id,
        "session_id": row.session_id,
        "detector_id": row.detector_id,
        "name": row.title,
        "severity": row.severity,
        "confidence": row.confidence,
        "src_ip": row.src_ip,
        "dst_ip": row.dst_ip,
        "src_port": row.src_port,
        "dst_port": row.dst_port,
        "protocol": row.protocol,
        "observed_at": isoformat(row.observed_at),
        "evidence": row.evidence,
        "recommended_action": row.recommended_action,
    }


def _indicator(row: Indicator) -> dict:
    return {
        "id": row.id,
        "indicator_type": row.indicator_type,
        "value": row.value,
        "observed_at": isoformat(row.observed_at),
        "alert_id": row.alert_id,
    }


def _timeline(row: TimelineEvent) -> dict:
    return {
        "id": row.id,
        "event_type": row.event_type,
        "severity": row.severity,
        "summary": row.summary,
        "occurred_at": isoformat(row.occurred_at),
        "alert_id": row.alert_id,
    }


def _timeline_key(row: TimelineEvent) -> tuple:
    if row.event_type == "analysis_started":
        group = 0
    elif row.event_type == "analysis_completed":
        group = 2
    else:
        group = 1
    return (group, row.occurred_at, row.id)


def _hosts(flows: list[FlowSummary]) -> list[dict]:
    hosts: dict[str, dict] = {}

    def slot(ip: str) -> dict:
        if ip not in hosts:
            hosts[ip] = {
                "ip": ip,
                "macs": set(),
                "packets_sent": 0,
                "packets_received": 0,
                "bytes_sent": 0,
                "bytes_received": 0,
                "role": _role(ip),
            }
        return hosts[ip]

    for flow in flows:
        source = slot(flow.src_ip)
        source["packets_sent"] += flow.packet_count
        source["bytes_sent"] += flow.byte_count
        if flow.src_mac:
            source["macs"].add(flow.src_mac)
        destination = slot(flow.dst_ip)
        destination["packets_received"] += flow.packet_count
        destination["bytes_received"] += flow.byte_count
        if flow.dst_mac:
            destination["macs"].add(flow.dst_mac)
    items = []
    for host in hosts.values():
        host["macs"] = sorted(host["macs"])
        items.append(host)
    items.sort(key=lambda item: item["bytes_sent"] + item["bytes_received"], reverse=True)
    return items


def _topology(flows: list[FlowSummary]) -> dict:
    volume: Counter[str] = Counter()
    for flow in flows:
        volume[flow.src_ip] += flow.byte_count
        volume[flow.dst_ip] += flow.byte_count
    kept = {ip for ip, _ in volume.most_common(8)}
    nodes = [{"id": ip, "ip": ip} for ip in sorted(kept)]
    links = []
    seen = set()
    for flow in flows:
        if flow.src_ip not in kept or flow.dst_ip not in kept or flow.src_ip == flow.dst_ip:
            continue
        key = (flow.src_ip, flow.dst_ip)
        if key in seen:
            continue
        seen.add(key)
        links.append({"source": flow.src_ip, "target": flow.dst_ip, "protocol": flow.protocol})
        if len(links) >= 12:
            break
    return {"nodes": nodes, "links": links}


def _role(ip: str) -> str:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if address.is_private or address.is_loopback:
        return "internal"
    return "external"


def _loads(value: str | None, fallback):
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback
