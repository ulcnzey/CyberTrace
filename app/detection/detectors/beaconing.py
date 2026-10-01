"""Repeated connections to one destination on a steady interval."""

from statistics import mean, pstdev

from app.core.domain import AnalysisContext, Detection

MIN_CONNECTIONS = 5
MIN_INTERVAL = 15
MAX_INTERVAL = 3600
MAX_VARIATION = 0.25


class BeaconingDetector:
    detector_id = "beaconing"
    name = "Beaconing"

    def analyze(self, context: AnalysisContext) -> list[Detection]:
        grouped: dict[tuple[str, str, int], list[tuple[float, str]]] = {}
        for flow in context.flows:
            if flow.protocol not in {"TCP", "UDP"} or flow.dst_port is None:
                continue
            key = (flow.src_ip, flow.dst_ip, flow.dst_port)
            grouped.setdefault(key, []).append((flow.started_at, flow.protocol))

        findings = []
        for (src_ip, dst_ip, dst_port), samples in grouped.items():
            ordered_samples = sorted(samples, key=lambda item: item[0])
            ordered = [item[0] for item in ordered_samples]
            protocol = ordered_samples[0][1]
            if len(ordered) < MIN_CONNECTIONS:
                continue
            intervals = [
                ordered[index + 1] - ordered[index]
                for index in range(len(ordered) - 1)
                if ordered[index + 1] > ordered[index]
            ]
            if len(intervals) < MIN_CONNECTIONS - 1:
                continue
            average = mean(intervals)
            if average < MIN_INTERVAL or average > MAX_INTERVAL:
                continue
            variation = pstdev(intervals) / average
            if variation > MAX_VARIATION:
                continue
            confidence = min(0.9, 0.64 + (0.25 - variation))
            findings.append(
                Detection(
                    detector_id=self.detector_id,
                    name=self.name,
                    confidence=confidence,
                    evidence=(
                        f"{src_ip} opened {len(ordered)} connections to "
                        f"{dst_ip}:{dst_port} about every {average:.0f} seconds."
                    ),
                    recommended_action=(
                        "Check this endpoint with the system owner. A steady connection "
                        "interval can be a scheduled client or automated polling."
                    ),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=protocol,
                    timestamp=ordered[0],
                )
            )
        return findings
