"""Severity is assigned separately from detector confidence."""

import unittest

from app.alerts.correlator import correlate
from app.core.domain import AlertRecord, AnalysisContext, Detection, HttpRequest
from app.ioc.extractor import extract_indicators
from app.risk.severity import apply_severity
from app.timeline.builder import build_timeline


class RiskTests(unittest.TestCase):
    def test_severity_does_not_change_confidence(self) -> None:
        finding = Detection(
            detector_id="horizontal_port_scan",
            name="Horizontal port scan",
            confidence=0.42,
            evidence="A scan was observed.",
            recommended_action="Review the source host.",
            src_ip="10.1.0.5",
        )
        apply_severity([finding])
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.confidence, 0.42)

    def test_unknown_detector_is_not_given_a_severity(self) -> None:
        finding = Detection(
            detector_id="not_a_rule",
            name="Not a rule",
            confidence=0.4,
            evidence="Something was seen.",
            recommended_action="Review.",
            src_ip="10.0.0.2",
        )
        self.assertEqual(apply_severity([finding]), [])
        self.assertEqual(finding.severity, "")

    def test_correlated_alert_keeps_both_fields(self) -> None:
        finding = Detection(
            detector_id="cleartext_telnet",
            name="Cleartext Telnet",
            confidence=0.9,
            evidence="Telnet port 23 was observed.",
            recommended_action="Disable Telnet.",
            src_ip="10.0.0.2",
            dst_ip="10.0.0.3",
            dst_port=23,
            protocol="TCP",
            timestamp=50,
            severity="high",
        )
        alerts = correlate([finding])
        self.assertEqual(alerts[0].severity, "high")
        self.assertEqual(alerts[0].confidence, 0.9)


class IndicatorTests(unittest.TestCase):
    def test_extractor_supports_the_required_types(self) -> None:
        finding = Detection(
            detector_id="dns_anomaly",
            name="DNS anomaly",
            confidence=0.8,
            evidence="Long DNS name.",
            recommended_action="Check the resolver.",
            src_ip="10.4.0.5",
            dst_ip="8.8.8.8",
            dst_port=53,
            protocol="DNS",
            timestamp=1_700_000_000,
            domain="long.example",
            macs=("aa:bb:cc:dd:ee:01",),
        )
        alert = AlertRecord(
            key="dns",
            detector_id=finding.detector_id,
            name=finding.name,
            severity="medium",
            confidence=finding.confidence,
            src_ip=finding.src_ip,
            dst_ip=finding.dst_ip,
            src_port=None,
            dst_port=53,
            protocol="DNS",
            timestamp=finding.timestamp,
            evidence=finding.evidence,
            recommended_action=finding.recommended_action,
            findings=[finding],
        )
        context = AnalysisContext(
            packets=[],
            flows=[],
            dns_queries=[],
            http_requests=[
                HttpRequest(
                    timestamp=1_700_000_000,
                    src_ip="10.4.0.5",
                    dst_ip="10.4.0.1",
                    dst_port=80,
                    method="GET",
                    host="lab.example",
                    path="/status",
                    user_agent="CyberTraceTest",
                )
            ],
        )
        kinds = {item.indicator_type for item in extract_indicators([alert], context)}
        self.assertTrue({"ip", "mac", "domain", "url", "port", "user_agent", "timestamp"} <= kinds)


class TimelineTests(unittest.TestCase):
    def test_events_are_chronological(self) -> None:
        alert = AlertRecord(
            key="scan",
            detector_id="horizontal_port_scan",
            name="Horizontal port scan",
            severity="high",
            confidence=0.6,
            src_ip="10.1.0.5",
            dst_ip=None,
            src_port=None,
            dst_port=22,
            protocol="TCP",
            timestamp=1_700_000_050,
            evidence="SYN packets to many hosts.",
            recommended_action="Review the source.",
        )
        items = build_timeline(
            started_at=1_700_000_000,
            ended_at=1_700_000_100,
            source_label="scan.pcap",
            protocol_events=[],
            alerts=[alert],
        )
        kinds = [item.event_type for item in items]
        self.assertEqual(kinds, ["analysis_started", "detection", "alert", "analysis_completed"])
        self.assertLessEqual(items[0].timestamp, items[1].timestamp)
        self.assertLessEqual(items[-2].timestamp, items[-1].timestamp)

    def test_historical_capture_stays_inside_the_session_boundaries(self) -> None:
        alert = AlertRecord(
            key="scan",
            detector_id="horizontal_port_scan",
            name="Horizontal port scan",
            severity="high",
            confidence=0.6,
            src_ip="10.1.0.5",
            dst_ip=None,
            src_port=None,
            dst_port=22,
            protocol="TCP",
            timestamp=1_700_000_000,
            evidence="SYN packets to many hosts.",
            recommended_action="Review the source.",
        )
        items = build_timeline(
            started_at=1_800_000_000,
            ended_at=1_800_000_010,
            source_label="old.pcap",
            protocol_events=[],
            alerts=[alert],
        )
        self.assertEqual(items[0].event_type, "analysis_started")
        self.assertEqual(items[-1].event_type, "analysis_completed")


if __name__ == "__main__":
    unittest.main()
