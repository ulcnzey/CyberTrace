"""Shared analysis pipeline for file captures and live traffic."""

from datetime import datetime, timezone

from app.alerts.correlator import correlate
from app.core.domain import NormalizedPacket, PipelineResult
from app.detection.engine import DetectionEngine
from app.features.extractors import build_context, protocol_observations
from app.features.flow_assembler import assemble_flows
from app.features.stats import traffic_statistics
from app.ioc.extractor import extract_indicators
from app.risk.severity import apply_severity
from app.timeline.builder import build_timeline

_STORE_FLOW_LIMIT = 2000


def run_pipeline(
    packets: list[NormalizedPacket],
    *,
    started_at: datetime,
    ended_at: datetime | None,
    source_label: str,
    warning: str | None = None,
) -> PipelineResult:
    flows = assemble_flows(packets)
    context = build_context(packets, flows)
    findings = apply_severity(DetectionEngine().run(context))
    alerts = correlate(findings)
    indicators = extract_indicators(alerts, context)
    events = protocol_observations(context)
    start_ts = started_at.timestamp()
    end_ts = ended_at.timestamp() if ended_at is not None else None
    timeline = build_timeline(
        started_at=start_ts,
        ended_at=end_ts,
        source_label=source_label,
        protocol_events=events,
        alerts=alerts,
    )
    protocol_counts, buckets, packet_count, byte_count = traffic_statistics(packets)
    stored_flows = _flows_to_keep(flows)
    flow_warning = None
    if len(flows) > len(stored_flows):
        flow_warning = f"Stored {len(stored_flows)} of {len(flows)} flow summaries."
    return PipelineResult(
        flows=stored_flows,
        protocol_events=events,
        findings=findings,
        alerts=alerts,
        indicators=indicators,
        timeline=timeline,
        packet_count=packet_count,
        byte_count=byte_count,
        protocol_counts=protocol_counts,
        traffic_buckets=buckets,
        warning=_join_warnings(warning, flow_warning),
    )


def _flows_to_keep(flows: list) -> list:
    if len(flows) <= _STORE_FLOW_LIMIT:
        return flows
    interesting = [flow for flow in flows if flow.syn_count or flow.protocol == "ARP"]
    rest = [flow for flow in flows if flow not in interesting]
    rest.sort(key=lambda flow: flow.byte_count, reverse=True)
    return (interesting + rest)[:_STORE_FLOW_LIMIT]


def _join_warnings(*parts: str | None) -> str | None:
    text = " ".join(part for part in parts if part)
    return text or None


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
