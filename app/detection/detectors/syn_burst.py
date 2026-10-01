"""Many SYN packets toward one host and port without completed handshakes."""

from app.core.domain import AnalysisContext, Detection

MIN_SYNS = 20


class SynBurstDetector:
    detector_id = "syn_burst"
    name = "SYN burst"

    def analyze(self, context: AnalysisContext) -> list[Detection]:
        grouped: dict[tuple[str, str, int], list] = {}
        for flow in context.flows:
            if flow.protocol != "TCP" or flow.dst_port is None:
                continue
            if flow.syn_count <= 0 or flow.ack_count != 0:
                continue
            key = (flow.src_ip, flow.dst_ip, flow.dst_port)
            grouped.setdefault(key, []).append(flow)

        findings = []
        for (src_ip, dst_ip, dst_port), flows in grouped.items():
            syns = sum(flow.syn_count for flow in flows)
            if syns < MIN_SYNS:
                continue
            start = min(flow.started_at for flow in flows)
            end = max(flow.ended_at for flow in flows)
            span = end - start
            if span > 120 and syns / span < 0.5:
                continue
            confidence = min(0.96, 0.58 + syns / 200)
            findings.append(
                Detection(
                    detector_id=self.detector_id,
                    name=self.name,
                    confidence=confidence,
                    evidence=(
                        f"{src_ip} sent {syns} SYN packets to {dst_ip}:{dst_port} "
                        "without completed handshakes."
                    ),
                    recommended_action=(
                        "Confirm whether this host is authorized to probe that service. "
                        "If the traffic is unexpected, isolate the source and rate-limit it."
                    ),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol="TCP",
                    timestamp=start,
                )
            )
        return findings
