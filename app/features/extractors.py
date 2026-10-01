"""Derive the feature context detectors read. Packets are not parsed again."""

from app.core.domain import (
    AnalysisContext,
    DnsQuery,
    FlowRecord,
    HttpRequest,
    NormalizedPacket,
    ProtocolObservation,
)


def build_context(
    packets: list[NormalizedPacket],
    flows: list[FlowRecord],
) -> AnalysisContext:
    dns_queries: list[DnsQuery] = []
    http_requests: list[HttpRequest] = []
    for packet in packets:
        if packet.dns_query:
            dns_queries.append(
                DnsQuery(
                    timestamp=packet.timestamp,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    qname=packet.dns_query,
                )
            )
        if packet.http_method:
            http_requests.append(
                HttpRequest(
                    timestamp=packet.timestamp,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    dst_port=packet.dst_port,
                    method=packet.http_method,
                    host=packet.http_host,
                    path=packet.http_path,
                    user_agent=packet.http_user_agent,
                )
            )
    return AnalysisContext(
        packets=packets,
        flows=flows,
        dns_queries=dns_queries,
        http_requests=http_requests,
    )


def protocol_observations(context: AnalysisContext) -> list[ProtocolObservation]:
    events: list[ProtocolObservation] = []
    seen_dns: set[tuple] = set()
    for query in context.dns_queries:
        key = (query.src_ip, query.qname)
        if key in seen_dns:
            continue
        seen_dns.add(key)
        events.append(
            ProtocolObservation(
                event_type="dns",
                timestamp=query.timestamp,
                summary=f"DNS query {query.qname}",
            )
        )
        if len(seen_dns) >= 80:
            break

    seen_http: set[tuple] = set()
    for request in context.http_requests:
        key = (request.src_ip, request.host, request.path)
        if key in seen_http:
            continue
        seen_http.add(key)
        target = request.host or request.dst_ip or "unknown host"
        path = request.path or "/"
        events.append(
            ProtocolObservation(
                event_type="http",
                timestamp=request.timestamp,
                summary=f"HTTP {request.method or 'request'} {target}{path}",
            )
        )
        if len(seen_http) >= 80:
            break

    seen_arp: set[tuple[str, str]] = set()
    for packet in context.packets:
        if packet.protocol != "ARP" or not packet.arp_psrc or not packet.arp_hwsrc:
            continue
        key = (packet.arp_psrc, packet.arp_hwsrc)
        if key in seen_arp:
            continue
        seen_arp.add(key)
        events.append(
            ProtocolObservation(
                event_type="arp",
                timestamp=packet.timestamp,
                summary=f"ARP {packet.arp_psrc} announced by {packet.arp_hwsrc}",
            )
        )
        if len(seen_arp) >= 80:
            break
    return events
