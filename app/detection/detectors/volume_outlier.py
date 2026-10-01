"""Large transfers from an internal address to an external address."""

import ipaddress

from app.config import settings
from app.core.domain import AnalysisContext, Detection


def is_internal(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return address.is_private or address.is_loopback


def is_external(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(address.is_global)


class LargeOutboundDetector:
    detector_id = "large_outbound"
    name = "Large outbound transfer"

    def analyze(self, context: AnalysisContext) -> list[Detection]:
        threshold = settings.large_outbound_bytes
        findings = []
        for flow in context.flows:
            if flow.protocol not in {"TCP", "UDP"}:
                continue
            if flow.byte_count < threshold:
                continue
            if not is_internal(flow.src_ip) or not is_external(flow.dst_ip):
                continue
            confidence = min(0.93, 0.62 + (flow.byte_count - threshold) / (threshold * 10))
            findings.append(
                Detection(
                    detector_id=self.detector_id,
                    name=self.name,
                    confidence=confidence,
                    evidence=(
                        f"{flow.src_ip} sent {flow.byte_count} bytes to "
                        f"{flow.dst_ip}:{flow.dst_port}."
                    ),
                    recommended_action=(
                        "Confirm this transfer with the host owner. Investigate the "
                        "destination if the volume was not expected."
                    ),
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    src_port=flow.src_port,
                    dst_port=flow.dst_port,
                    protocol=flow.protocol,
                    timestamp=flow.started_at,
                )
            )
        return findings
