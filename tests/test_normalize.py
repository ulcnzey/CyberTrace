"""Packet normalization keeps headers and drops payload contents."""

import unittest

from app.ingestion.normalizer import normalize_packet


class NormalizeTests(unittest.TestCase):
    def test_tcp_syn_flags_and_endpoints(self) -> None:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether

        packet = Ether() / IP(src="10.0.0.8", dst="10.0.0.9") / TCP(sport=1234, dport=443, flags="S")
        packet.time = 1_700_000_000
        normalized = normalize_packet(packet)
        self.assertEqual(normalized.src_ip, "10.0.0.8")
        self.assertEqual(normalized.dst_ip, "10.0.0.9")
        self.assertEqual(normalized.dst_port, 443)
        self.assertEqual(normalized.protocol, "TCP")
        self.assertIn("S", normalized.tcp_flags or "")
        self.assertNotIn("A", normalized.tcp_flags or "")
        self.assertEqual(normalized.timestamp, 1_700_000_000)

    def test_dns_query_name(self) -> None:
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import IP, UDP
        from scapy.layers.l2 import Ether

        packet = Ether() / IP(src="10.0.0.2", dst="1.1.1.1") / UDP(sport=1111, dport=53) / DNS(
            rd=1, qd=DNSQR(qname="Example.COM")
        )
        normalized = normalize_packet(packet)
        self.assertEqual(normalized.dns_query, "example.com")
        self.assertEqual(normalized.protocol, "UDP")

    def test_http_metadata_does_not_keep_the_body(self) -> None:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        payload = b"GET /status HTTP/1.1\r\nHost: lab.example\r\nUser-Agent: CyberTraceTest\r\n\r\nsecret-token"
        packet = Ether() / IP(src="10.0.0.2", dst="10.0.0.3") / TCP(sport=2222, dport=80, flags="PA") / Raw(load=payload)
        normalized = normalize_packet(packet)
        self.assertEqual(normalized.http_method, "GET")
        self.assertEqual(normalized.http_host, "lab.example")
        self.assertEqual(normalized.http_user_agent, "CyberTraceTest")
        stored = " ".join(
            str(value)
            for value in (
                normalized.http_path,
                normalized.http_host,
                normalized.http_user_agent,
                normalized.http_method,
            )
        )
        self.assertNotIn("secret-token", stored)
        self.assertFalse(hasattr(normalized, "payload"))

    def test_arp_claim(self) -> None:
        from scapy.layers.l2 import ARP, Ether

        packet = Ether(src="aa:bb:cc:dd:ee:01") / ARP(
            op=2, psrc="10.9.0.4", hwsrc="AA:BB:CC:DD:EE:01", pdst="10.9.0.1"
        )
        normalized = normalize_packet(packet)
        self.assertEqual(normalized.protocol, "ARP")
        self.assertEqual(normalized.arp_psrc, "10.9.0.4")
        self.assertEqual(normalized.arp_hwsrc, "aa:bb:cc:dd:ee:01")
        self.assertEqual(normalized.arp_op, "reply")


if __name__ == "__main__":
    unittest.main()
