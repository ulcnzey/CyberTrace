"""Flow assembly from normalized packets."""

import unittest

from tests.support import context_from, packet


class FlowAssemblyTests(unittest.TestCase):
    def test_syn_and_ack_are_counted_on_one_flow(self) -> None:
        packets = [
            packet(tcp_flags="S", timestamp=10),
            packet(tcp_flags="A", timestamp=11, length=80),
        ]
        _context, flows = context_from(packets)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].packet_count, 2)
        self.assertEqual(flows[0].byte_count, 140)
        self.assertEqual(flows[0].syn_count, 1)
        self.assertEqual(flows[0].ack_count, 1)
        self.assertEqual(flows[0].started_at, 10)
        self.assertEqual(flows[0].ended_at, 11)

    def test_different_directions_stay_separate(self) -> None:
        packets = [
            packet(src_ip="10.0.0.2", dst_ip="10.0.0.3", src_port=1, dst_port=80),
            packet(src_ip="10.0.0.3", dst_ip="10.0.0.2", src_port=80, dst_port=1),
        ]
        _context, flows = context_from(packets)
        self.assertEqual(len(flows), 2)

    def test_arp_claims_with_different_macs_are_not_merged(self) -> None:
        packets = [
            packet(protocol="ARP", src_ip="10.5.0.9", dst_ip="10.5.0.1", src_port=None, dst_port=None, src_mac="aa:bb:cc:dd:ee:01", tcp_flags=None),
            packet(protocol="ARP", src_ip="10.5.0.9", dst_ip="10.5.0.1", src_port=None, dst_port=None, src_mac="aa:bb:cc:dd:ee:02", tcp_flags=None),
        ]
        _context, flows = context_from(packets)
        self.assertEqual(len(flows), 2)


if __name__ == "__main__":
    unittest.main()
