"""One source contacting the same port on many hosts."""

from app.core.domain import AnalysisContext, Detection

MIN_HOSTS = 8


class HorizontalPortScanDetector:
    detector_id = "horizontal_port_scan"
    name = "Horizontal port scan"

    def analyze(self, context: AnalysisContext) -> list[Detection]:
        destinations: dict[tuple[str, int], set[str]] = {}
        syn_destinations: dict[tuple[str, int], set[str]] = {}
        first_seen: dict[tuple[str, int], float] = {}
        for flow in context.flows:
            if flow.protocol != "TCP" or flow.dst_port is None:
                continue
            key = (flow.src_ip, flow.dst_port)
            destinations.setdefault(key, set()).add(flow.dst_ip)
            first_seen.setdefault(key, flow.started_at)
            if flow.syn_count > 0 and flow.ack_count == 0:
                syn_destinations.setdefault(key, set()).add(flow.dst_ip)

        findings = []
        for key, hosts in syn_destinations.items():
            if len(hosts) < MIN_HOSTS:
                continue
            all_hosts = destinations.get(key, hosts)
            if len(hosts) / max(len(all_hosts), 1) < 0.7:
                continue
            src_ip, dst_port = key
            sample = ", ".join(sorted(hosts)[:8])
            confidence = min(0.98, 0.55 + (len(hosts) - MIN_HOSTS) / 40)
            findings.append(
                Detection(
                    detector_id=self.detector_id,
                    name=self.name,
                    confidence=confidence,
                    evidence=(
                        f"{src_ip} sent SYN packets to port {dst_port} on "
                        f"{len(hosts)} destinations ({sample})."
                    ),
                    recommended_action=(
                        "Verify this scan was authorized. If it was not, isolate the "
                        "source host and review which destinations responded."
                    ),
                    src_ip=src_ip,
                    dst_port=dst_port,
                    protocol="TCP",
                    timestamp=first_seen.get(key),
                )
            )
        return findings
