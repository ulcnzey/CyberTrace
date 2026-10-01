"""In-memory objects shared by PCAP analysis and live capture.

These objects are not stored as raw packets. Persistence keeps summaries,
findings, alerts, indicators, and timeline entries.
"""

from dataclasses import dataclass, field


@dataclass
class NormalizedPacket:
    timestamp: float
    length: int
    src_ip: str | None = None
    dst_ip: str | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "OTHER"
    tcp_flags: str | None = None
    dns_query: str | None = None
    http_host: str | None = None
    http_path: str | None = None
    http_user_agent: str | None = None
    http_method: str | None = None
    icmp_type: int | None = None
    icmp_payload_len: int = 0
    arp_op: str | None = None
    arp_psrc: str | None = None
    arp_hwsrc: str | None = None


@dataclass
class FlowRecord:
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    src_mac: str | None
    dst_mac: str | None
    packet_count: int
    byte_count: int
    started_at: float
    ended_at: float
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0


@dataclass
class DnsQuery:
    timestamp: float
    src_ip: str | None
    dst_ip: str | None
    qname: str


@dataclass
class HttpRequest:
    timestamp: float
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    method: str | None
    host: str | None
    path: str | None
    user_agent: str | None


@dataclass
class Detection:
    """A detector result. Confidence is set by the detector. Severity is not."""

    detector_id: str
    name: str
    confidence: float
    evidence: str
    recommended_action: str
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    timestamp: float | None = None
    domain: str | None = None
    url: str | None = None
    user_agent: str | None = None
    macs: tuple[str, ...] = ()
    severity: str = ""

    def __post_init__(self) -> None:
        self.confidence = round(min(1.0, max(0.0, float(self.confidence))), 4)


@dataclass
class AnalysisContext:
    packets: list[NormalizedPacket]
    flows: list[FlowRecord]
    dns_queries: list[DnsQuery]
    http_requests: list[HttpRequest]


@dataclass
class ProtocolObservation:
    event_type: str
    timestamp: float | None
    summary: str


@dataclass
class AlertRecord:
    key: str
    detector_id: str
    name: str
    severity: str
    confidence: float
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str | None
    timestamp: float | None
    evidence: str
    recommended_action: str
    findings: list[Detection] = field(default_factory=list)


@dataclass
class IndicatorRecord:
    indicator_type: str
    value: str
    timestamp: float | None
    alert_key: str | None = None


@dataclass
class TimelineItem:
    timestamp: float
    event_type: str
    summary: str
    severity: str | None = None
    alert_key: str | None = None
    rank: int = 0


@dataclass
class PipelineResult:
    flows: list[FlowRecord]
    protocol_events: list[ProtocolObservation]
    findings: list[Detection]
    alerts: list[AlertRecord]
    indicators: list[IndicatorRecord]
    timeline: list[TimelineItem]
    packet_count: int
    byte_count: int
    protocol_counts: dict[str, int]
    traffic_buckets: list[dict]
    warning: str | None = None
