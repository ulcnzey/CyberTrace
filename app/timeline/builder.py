"""Build a chronological timeline from session boundaries, protocol events, and alerts."""

from app.core.domain import AlertRecord, ProtocolObservation, TimelineItem


def build_timeline(
    *,
    started_at: float,
    ended_at: float | None,
    source_label: str,
    protocol_events: list[ProtocolObservation],
    alerts: list[AlertRecord],
) -> list[TimelineItem]:
    items = [
        TimelineItem(
            timestamp=started_at,
            event_type="analysis_started",
            summary=f"Analysis started for {source_label}.",
            rank=0,
        )
    ]
    for event in protocol_events[:12]:
        if event.timestamp is None:
            continue
        items.append(
            TimelineItem(
                timestamp=event.timestamp,
                event_type="protocol",
                summary=event.summary,
                rank=1,
            )
        )
    for alert in alerts:
        if alert.timestamp is None:
            continue
        when = alert.timestamp
        items.append(
            TimelineItem(
                timestamp=when,
                event_type="detection",
                summary=f"{alert.name}: {alert.evidence}",
                severity=alert.severity,
                alert_key=alert.key,
                rank=2,
            )
        )
        items.append(
            TimelineItem(
                timestamp=when,
                event_type="alert",
                summary=f"{alert.severity} severity alert: {alert.name}.",
                severity=alert.severity,
                alert_key=alert.key,
                rank=3,
            )
        )
    if ended_at is not None:
        items.append(
            TimelineItem(
                timestamp=ended_at,
                event_type="analysis_completed",
                summary="Analysis completed.",
                rank=4,
            )
        )
    items.sort(key=_order)
    return items


def _order(item: TimelineItem) -> tuple:
    if item.event_type == "analysis_started":
        group = 0
    elif item.event_type == "analysis_completed":
        group = 2
    else:
        group = 1
    return (group, item.timestamp, item.rank)
