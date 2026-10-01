"""Assign severity from detector policy. Confidence is left unchanged."""

SEVERITY_BY_DETECTOR = {
    "horizontal_port_scan": "high",
    "vertical_port_scan": "high",
    "syn_burst": "medium",
    "beaconing": "medium",
    "dns_anomaly": "medium",
    "icmp_anomaly": "low",
    "cleartext_telnet": "high",
    "cleartext_ftp": "medium",
    "large_outbound": "medium",
    "arp_multi_mac": "high",
}

SEVERITIES = ("info", "low", "medium", "high", "critical")


def apply_severity(findings: list) -> list:
    for finding in findings:
        finding.severity = SEVERITY_BY_DETECTOR.get(finding.detector_id, "low")
    return findings
