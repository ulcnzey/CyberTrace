"""Pull indicators from alerts and the related protocol context."""

from app.core.clock import from_timestamp, isoformat
from app.core.domain import AlertRecord, AnalysisContext, IndicatorRecord


def extract_indicators(
    alerts: list[AlertRecord],
    context: AnalysisContext,
) -> list[IndicatorRecord]:
    indicators: list[IndicatorRecord] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str | None, timestamp: float | None, alert_key: str | None) -> None:
        if value is None:
            return
        text = str(value).strip()
        if not text:
            return
        marker = (kind, text.lower())
        if marker in seen:
            return
        seen.add(marker)
        indicators.append(
            IndicatorRecord(
                indicator_type=kind,
                value=text[:1024],
                timestamp=timestamp,
                alert_key=alert_key,
            )
        )

    for alert in alerts:
        add("ip", alert.src_ip, alert.timestamp, alert.key)
        add("ip", alert.dst_ip, alert.timestamp, alert.key)
        if alert.dst_port is not None:
            add("port", str(alert.dst_port), alert.timestamp, alert.key)
        if alert.timestamp is not None:
            add("timestamp", isoformat(from_timestamp(alert.timestamp)), alert.timestamp, alert.key)

        involved = {ip for ip in (alert.src_ip, alert.dst_ip) if ip}
        for finding in alert.findings:
            add("domain", finding.domain, finding.timestamp, alert.key)
            add("url", finding.url, finding.timestamp, alert.key)
            add("user_agent", finding.user_agent, finding.timestamp, alert.key)
            for mac in finding.macs:
                add("mac", mac, finding.timestamp, alert.key)

        for request in context.http_requests:
            hosts = {request.src_ip, request.dst_ip}
            if involved and not involved.intersection(hosts):
                continue
            if request.host:
                add("domain", request.host, request.timestamp, alert.key)
                path = request.path or "/"
                add("url", f"http://{request.host}{path}", request.timestamp, alert.key)
            add("user_agent", request.user_agent, request.timestamp, alert.key)
    return indicators
