"""End-to-end PCAP scenarios through the shared pipeline."""

import tempfile
import unittest
from pathlib import Path

from app.services.analysis_service import analyze_capture_file
from app.services.read_models import list_alerts, list_iocs
from tests.captures import (
    arp_conflict_packets,
    dns_anomaly_packets,
    horizontal_scan_packets,
    normal_packets,
    syn_burst_packets,
    write_capture,
)
from tests.support import reset_db


class PcapScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_db()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def analyze(self, packets: list, name: str) -> dict:
        path = Path(self.temp.name) / name
        write_capture(path, packets)
        return analyze_capture_file(path, name)

    def detector_ids(self, detail: dict) -> set[str]:
        payload = list_alerts(detail["id"]) or {"items": []}
        return {item["detector_id"] for item in payload["items"]}

    def test_normal_traffic_has_no_alerts(self) -> None:
        detail = self.analyze(normal_packets(), "normal.pcap")
        self.assertEqual(detail["status"], "completed")
        self.assertGreater(detail["packet_count"], 0)
        self.assertEqual(self.detector_ids(detail), set())

    def test_port_scan_pcap(self) -> None:
        detail = self.analyze(horizontal_scan_packets(), "scan.pcap")
        alerts = (list_alerts(detail["id"]) or {"items": []})["items"]
        self.assertEqual(alerts[0]["detector_id"], "horizontal_port_scan")
        self.assertEqual(alerts[0]["severity"], "high")
        self.assertAlmostEqual(alerts[0]["confidence"], 0.6)
        kinds = {item["indicator_type"] for item in (list_iocs(detail["id"]) or {"items": []})["items"]}
        self.assertIn("ip", kinds)
        self.assertIn("port", kinds)
        self.assertIn("timestamp", kinds)

    def test_syn_anomaly_pcap(self) -> None:
        detail = self.analyze(syn_burst_packets(), "syn.pcap")
        self.assertIn("syn_burst", self.detector_ids(detail))

    def test_dns_anomaly_pcap(self) -> None:
        detail = self.analyze(dns_anomaly_packets(), "dns.pcap")
        self.assertIn("dns_anomaly", self.detector_ids(detail))
        values = [item["value"] for item in (list_iocs(detail["id"]) or {"items": []})["items"]]
        self.assertTrue(any("aaaa" in value for value in values))

    def test_arp_suspicious_mapping_pcap(self) -> None:
        detail = self.analyze(arp_conflict_packets(), "arp.pcap")
        self.assertIn("arp_multi_mac", self.detector_ids(detail))
        kinds = {item["indicator_type"] for item in (list_iocs(detail["id"]) or {"items": []})["items"]}
        self.assertIn("mac", kinds)


if __name__ == "__main__":
    unittest.main()
