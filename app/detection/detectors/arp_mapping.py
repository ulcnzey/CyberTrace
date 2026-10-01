"""One IP address announced by more than one MAC address."""

from app.core.domain import AnalysisContext, Detection


class ArpMappingDetector:
    detector_id = "arp_multi_mac"
    name = "Suspicious ARP mapping"

    def analyze(self, context: AnalysisContext) -> list[Detection]:
        macs_for_ip: dict[str, set[str]] = {}
        first_seen: dict[str, float] = {}
        for packet in context.packets:
            if packet.protocol != "ARP" or not packet.arp_psrc or not packet.arp_hwsrc:
                continue
            claimed_ip = packet.arp_psrc
            claimed_mac = packet.arp_hwsrc.lower()
            macs_for_ip.setdefault(claimed_ip, set()).add(claimed_mac)
            first_seen.setdefault(claimed_ip, packet.timestamp)

        findings = []
        for claimed_ip, macs in macs_for_ip.items():
            if len(macs) < 2:
                continue
            ordered = tuple(sorted(macs))
            confidence = min(0.97, 0.7 + 0.08 * (len(ordered) - 2))
            findings.append(
                Detection(
                    detector_id=self.detector_id,
                    name=self.name,
                    confidence=confidence,
                    evidence=(
                        f"IP {claimed_ip} was announced by {len(ordered)} MAC addresses: "
                        + ", ".join(ordered)
                        + "."
                    ),
                    recommended_action=(
                        "Check for a misconfigured host or ARP spoofing on this segment. "
                        "Compare the addresses with the asset inventory before trusting the mapping."
                    ),
                    src_ip=claimed_ip,
                    protocol="ARP",
                    timestamp=first_seen.get(claimed_ip),
                    macs=ordered,
                )
            )
        return findings
