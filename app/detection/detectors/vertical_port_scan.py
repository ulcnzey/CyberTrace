"""One source probing many ports on a single host."""

from app.core.domain import AnalysisContext, Detection

MIN_PORTS = 10


class VerticalPortScanDetector:
    detector_id = "vertical_port_scan"
    name = "Vertical port scan"

    def analyze(self, context: AnalysisContext) -> list[Detection]:
        ports: dict[tuple[str, str], set[int]] = {}
        first_seen: dict[tuple[str, str], float] = {}
        for flow in context.flows:
            if flow.protocol != "TCP" or flow.dst_port is None:
                continue
            if flow.syn_count <= 0 or flow.ack_count != 0:
                continue
            key = (flow.src_ip, flow.dst_ip)
            ports.setdefault(key, set()).add(flow.dst_port)
            first_seen.setdefault(key, flow.started_at)

        findings = []
        for (src_ip, dst_ip), scanned in ports.items():
            if len(scanned) < MIN_PORTS:
                continue
            sample = ", ".join(str(port) for port in sorted(scanned)[:8])
            confidence = min(0.98, 0.55 + (len(scanned) - MIN_PORTS) / 40)
            findings.append(
                Detection(
                    detector_id=self.detector_id,
                    name=self.name,
                    confidence=confidence,
                    evidence=(
                        f"{src_ip} sent SYN packets to {len(scanned)} ports on "
                        f"{dst_ip} ({sample})."
                    ),
                    recommended_action=(
                        "Confirm this was an approved assessment. Review exposed "
                        "services on the destination if the scan was unexpected."
                    ),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol="TCP",
                    timestamp=first_seen.get((src_ip, dst_ip)),
                )
            )
        return findings
