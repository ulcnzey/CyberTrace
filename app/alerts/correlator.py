"""Group findings into alerts. Severity and confidence stay separate fields."""

from app.core.domain import AlertRecord, Detection


def _key(finding: Detection) -> str:
    return "|".join(
        [
            finding.detector_id,
            finding.src_ip or "",
            finding.dst_ip or "",
            str(finding.dst_port or ""),
            finding.domain or "",
        ]
    )


def correlate(findings: list[Detection]) -> list[AlertRecord]:
    grouped: dict[str, list[Detection]] = {}
    for finding in findings:
        grouped.setdefault(_key(finding), []).append(finding)

    alerts = []
    for key, items in grouped.items():
        primary = max(items, key=lambda item: item.confidence)
        evidence = " ".join(dict.fromkeys(item.evidence for item in items))
        timestamp = min(
            (item.timestamp for item in items if item.timestamp is not None),
            default=None,
        )
        alerts.append(
            AlertRecord(
                key=key,
                detector_id=primary.detector_id,
                name=primary.name,
                severity=primary.severity,
                confidence=primary.confidence,
                src_ip=primary.src_ip,
                dst_ip=primary.dst_ip,
                src_port=primary.src_port,
                dst_port=primary.dst_port,
                protocol=primary.protocol,
                timestamp=timestamp,
                evidence=evidence[:4000],
                recommended_action=primary.recommended_action,
                findings=items,
            )
        )
    alerts.sort(key=lambda alert: (alert.timestamp is None, alert.timestamp or 0))
    return alerts
