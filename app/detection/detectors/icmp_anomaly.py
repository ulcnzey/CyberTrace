"""ICMP sweeps and unusually large ICMP payloads."""

from app.core.domain import AnalysisContext, Detection

MIN_ECHO_DESTINATIONS = 10
LARGE_PAYLOAD = 300


class IcmpAnomalyDetector:
    detector_id = "icmp_anomaly"
    name = "ICMP anomaly"

    def analyze(self, context: AnalysisContext) -> list[Detection]:
        echoes: dict[str, set[str]] = {}
        first_seen: dict[str, float] = {}
        findings = []
        reported_large: set[tuple[str, str]] = set()
        for packet in context.packets:
            if packet.protocol != "ICMP" or not packet.src_ip:
                continue
            if packet.icmp_type == 8 and packet.dst_ip:
                echoes.setdefault(packet.src_ip, set()).add(packet.dst_ip)
                first_seen.setdefault(packet.src_ip, packet.timestamp)
            if packet.icmp_payload_len >= LARGE_PAYLOAD and packet.dst_ip:
                key = (packet.src_ip, packet.dst_ip)
                if key in reported_large:
                    continue
                reported_large.add(key)
                confidence = min(
                    0.95,
                    0.6 + (packet.icmp_payload_len - LARGE_PAYLOAD) / 2000,
                )
                findings.append(
                    Detection(
                        detector_id=self.detector_id,
                        name=self.name,
                        confidence=confidence,
                        evidence=(
                            f"ICMP payload of {packet.icmp_payload_len} bytes from "
                            f"{packet.src_ip} to {packet.dst_ip}."
                        ),
                        recommended_action=(
                            "Confirm whether a large ICMP payload is part of an approved test. "
                            "Otherwise, inspect the sending host."
                        ),
                        src_ip=packet.src_ip,
                        dst_ip=packet.dst_ip,
                        protocol="ICMP",
                        timestamp=packet.timestamp,
                    )
                )

        for src_ip, destinations in echoes.items():
            if len(destinations) < MIN_ECHO_DESTINATIONS:
                continue
            confidence = min(0.92, 0.58 + len(destinations) / 80)
            findings.append(
                Detection(
                    detector_id=self.detector_id,
                    name=self.name,
                    confidence=confidence,
                    evidence=(
                        f"{src_ip} sent ICMP echo requests to {len(destinations)} destinations."
                    ),
                    recommended_action=(
                        "Confirm whether this echo sweep is an approved discovery test. "
                        "If it is not, isolate the source host."
                    ),
                    src_ip=src_ip,
                    protocol="ICMP",
                    timestamp=first_seen.get(src_ip),
                )
            )
        return findings
