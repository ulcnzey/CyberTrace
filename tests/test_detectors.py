"""Each detector is independent and reports its own confidence."""

import unittest

from app.detection.detectors.arp_mapping import ArpMappingDetector
from app.detection.detectors.beaconing import BeaconingDetector
from app.detection.detectors.cleartext_protocol import FtpDetector, TelnetDetector
from app.detection.detectors.dns_anomaly import DnsAnomalyDetector
from app.detection.detectors.icmp_anomaly import IcmpAnomalyDetector
from app.detection.detectors.port_scan import HorizontalPortScanDetector
from app.detection.detectors.syn_burst import SynBurstDetector
from app.detection.detectors.vertical_port_scan import VerticalPortScanDetector
from app.detection.detectors.volume_outlier import LargeOutboundDetector
from app.detection.engine import DetectionEngine
from app.detection.registry import default_detectors
from tests.support import context_from, packet


def ids(findings) -> set[str]:
    return {finding.detector_id for finding in findings}


class DetectorTests(unittest.TestCase):
    def test_registry_lists_the_required_detectors(self) -> None:
        found = {detector.detector_id for detector in default_detectors()}
        self.assertEqual(
            found,
            {
                "horizontal_port_scan",
                "vertical_port_scan",
                "syn_burst",
                "beaconing",
                "dns_anomaly",
                "icmp_anomaly",
                "cleartext_telnet",
                "cleartext_ftp",
                "large_outbound",
                "arp_multi_mac",
            },
        )

    def test_horizontal_port_scan(self) -> None:
        packets = [
            packet(src_ip="10.1.0.5", dst_ip=f"10.1.0.{index}", src_port=41000 + index, dst_port=22, tcp_flags="S", timestamp=100 + index)
            for index in range(1, 11)
        ]
        context, _flows = context_from(packets)
        findings = HorizontalPortScanDetector().analyze(context)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector_id, "horizontal_port_scan")
        self.assertAlmostEqual(findings[0].confidence, 0.6)
        self.assertEqual(findings[0].severity, "")

    def test_vertical_port_scan(self) -> None:
        packets = [
            packet(src_ip="10.2.0.5", dst_ip="10.2.0.9", src_port=42000 + port, dst_port=port, tcp_flags="S", timestamp=200 + port)
            for port in range(20, 32)
        ]
        context, _flows = context_from(packets)
        findings = VerticalPortScanDetector().analyze(context)
        self.assertEqual(len(findings), 1)
        self.assertAlmostEqual(findings[0].confidence, 0.6)
        self.assertEqual(findings[0].dst_ip, "10.2.0.9")

    def test_syn_burst(self) -> None:
        packets = [
            packet(src_ip="10.3.0.5", dst_ip="10.3.0.9", src_port=50000 + index, dst_port=80, tcp_flags="S", timestamp=300 + index * 0.01)
            for index in range(20)
        ]
        context, _flows = context_from(packets)
        findings = SynBurstDetector().analyze(context)
        self.assertEqual(len(findings), 1)
        self.assertAlmostEqual(findings[0].confidence, 0.68)

    def test_beaconing(self) -> None:
        packets = [
            packet(src_ip="10.9.0.2", dst_ip="203.0.113.10", src_port=44000 + index, dst_port=443, tcp_flags="S", timestamp=1_700_000_000 + index * 60)
            for index in range(6)
        ]
        context, _flows = context_from(packets)
        findings = BeaconingDetector().analyze(context)
        self.assertEqual(len(findings), 1)
        self.assertAlmostEqual(findings[0].confidence, 0.89)

    def test_dns_anomaly_and_benign_name(self) -> None:
        context, _flows = context_from([
            packet(protocol="UDP", src_port=53000, dst_port=53, dst_ip="8.8.8.8", tcp_flags=None, dns_query=("a" * 40) + ".example.com"),
        ])
        findings = DnsAnomalyDetector().analyze(context)
        self.assertEqual(findings[0].confidence, 0.84)
        self.assertEqual(findings[0].domain, ("a" * 40) + ".example.com")
        benign, _flows = context_from([
            packet(protocol="UDP", src_port=53000, dst_port=53, tcp_flags=None, dns_query="example.com"),
        ])
        self.assertEqual(DnsAnomalyDetector().analyze(benign), [])

    def test_icmp_sweep(self) -> None:
        packets = [
            packet(protocol="ICMP", src_ip="10.8.0.5", dst_ip=f"10.8.0.{index}", src_port=None, dst_port=None, tcp_flags=None, icmp_type=8)
            for index in range(1, 13)
        ]
        context, _flows = context_from(packets)
        findings = IcmpAnomalyDetector().analyze(context)
        self.assertEqual(len(findings), 1)
        self.assertAlmostEqual(findings[0].confidence, 0.73)

    def test_cleartext_ports_do_not_read_payload(self) -> None:
        telnet, _flows = context_from([
            packet(dst_port=23, tcp_flags="S"),
            packet(dst_port=23, tcp_flags="A"),
        ])
        ftp, _flows = context_from([packet(dst_port=21, tcp_flags="S")])
        telnet_findings = TelnetDetector().analyze(telnet)
        ftp_findings = FtpDetector().analyze(ftp)
        self.assertEqual(telnet_findings[0].confidence, 0.9)
        self.assertEqual(ftp_findings[0].confidence, 0.66)
        self.assertNotIn("password", telnet_findings[0].evidence.lower())

    def test_large_outbound(self) -> None:
        packets = [
            packet(src_ip="10.7.0.2", dst_ip="8.8.8.8", dst_port=443, length=1500, tcp_flags="A", timestamp=500 + index)
            for index in range(70)
        ]
        context, _flows = context_from(packets)
        findings = LargeOutboundDetector().analyze(context)
        self.assertEqual(len(findings), 1)
        self.assertGreater(findings[0].confidence, 0.6)
        self.assertLess(findings[0].confidence, 0.7)

    def test_arp_multiple_macs(self) -> None:
        packets = [
            packet(protocol="ARP", src_ip="10.5.0.9", dst_ip="10.5.0.1", src_port=None, dst_port=None, tcp_flags=None, arp_psrc="10.5.0.9", arp_hwsrc="aa:bb:cc:dd:ee:01"),
            packet(protocol="ARP", src_ip="10.5.0.9", dst_ip="10.5.0.1", src_port=None, dst_port=None, tcp_flags=None, arp_psrc="10.5.0.9", arp_hwsrc="aa:bb:cc:dd:ee:02"),
        ]
        context, _flows = context_from(packets)
        findings = ArpMappingDetector().analyze(context)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].confidence, 0.7)
        self.assertEqual(findings[0].macs, ("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"))

    def test_normal_traffic_has_no_detections(self) -> None:
        packets = [
            packet(tcp_flags="S", timestamp=1),
            packet(src_ip="10.0.0.3", dst_ip="10.0.0.2", src_port=80, dst_port=40000, tcp_flags="SA", timestamp=1.1),
            packet(tcp_flags="A", timestamp=1.2),
            packet(protocol="UDP", dst_ip="8.8.8.8", dst_port=53, src_port=53000, tcp_flags=None, dns_query="example.com"),
            packet(protocol="ICMP", src_port=None, dst_port=None, tcp_flags=None, icmp_type=8),
            packet(protocol="ARP", src_port=None, dst_port=None, tcp_flags=None, arp_psrc="10.0.0.2", arp_hwsrc="aa:bb:cc:dd:ee:10", src_mac="aa:bb:cc:dd:ee:10"),
        ]
        context, _flows = context_from(packets)
        self.assertEqual(DetectionEngine().run(context), [])

    def test_one_failing_detector_does_not_stop_the_others(self) -> None:
        class Broken:
            detector_id = "broken"
            name = "Broken"

            def analyze(self, _context):
                raise RuntimeError("detector failed")

        class Healthy:
            detector_id = "healthy"
            name = "Healthy"

            def analyze(self, _context):
                from app.core.domain import Detection

                return [Detection("healthy", "Healthy", 0.5, "evidence", "review", src_ip="10.0.0.2")]

        context, _flows = context_from([packet()])
        findings = DetectionEngine([Broken(), Healthy()]).run(context)
        self.assertEqual(ids(findings), {"healthy"})


if __name__ == "__main__":
    unittest.main()
