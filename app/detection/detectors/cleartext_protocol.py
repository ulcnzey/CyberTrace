"""Detect Telnet and FTP by destination port. Payloads are not inspected or stored."""

from app.core.domain import AnalysisContext, Detection


class _CleartextDetector:
    detector_id = ""
    name = ""
    port = 0
    service = ""
    base_confidence = 0.7
    established_confidence = 0.9
    recommended_action = ""

    def analyze(self, context: AnalysisContext) -> list[Detection]:
        findings = []
        seen: set[tuple[str, str]] = set()
        for flow in context.flows:
            if flow.protocol != "TCP" or flow.dst_port != self.port:
                continue
            key = (flow.src_ip, flow.dst_ip)
            if key in seen:
                continue
            seen.add(key)
            established = flow.ack_count > 0
            confidence = self.established_confidence if established else self.base_confidence
            state = "an established connection" if established else "connection attempts"
            findings.append(
                Detection(
                    detector_id=self.detector_id,
                    name=self.name,
                    confidence=confidence,
                    evidence=(
                        f"{state.capitalize()} to {self.service} port {self.port} "
                        f"from {flow.src_ip} to {flow.dst_ip} ({flow.packet_count} packets)."
                    ),
                    recommended_action=self.recommended_action,
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    src_port=flow.src_port,
                    dst_port=flow.dst_port,
                    protocol="TCP",
                    timestamp=flow.started_at,
                )
            )
        return findings


class TelnetDetector(_CleartextDetector):
    detector_id = "cleartext_telnet"
    name = "Cleartext Telnet"
    port = 23
    service = "Telnet"
    recommended_action = (
        "Telnet exposes session content on the network. Disable Telnet and use SSH "
        "on the affected hosts."
    )


class FtpDetector(_CleartextDetector):
    detector_id = "cleartext_ftp"
    name = "Cleartext FTP"
    port = 21
    service = "FTP"
    base_confidence = 0.66
    established_confidence = 0.86
    recommended_action = (
        "FTP was observed. Prefer encrypted file transfer and disable cleartext FTP "
        "where it is not required."
    )
