"""Small synthetic captures used by integration tests."""

from pathlib import Path


def _stamp(packet, when: float):
    packet.time = when
    return packet


def normal_packets() -> list:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether

    handshake = [
        _stamp(Ether() / IP(src="10.0.0.2", dst="10.0.0.3") / TCP(sport=12345, dport=80, flags="S"), 1_700_000_000),
        _stamp(Ether() / IP(src="10.0.0.3", dst="10.0.0.2") / TCP(sport=80, dport=12345, flags="SA"), 1_700_000_000.1),
        _stamp(Ether() / IP(src="10.0.0.2", dst="10.0.0.3") / TCP(sport=12345, dport=80, flags="A"), 1_700_000_000.2),
    ]
    dns = _stamp(
        Ether() / IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")),
        1_700_000_001,
    )
    arp = _stamp(
        Ether(src="aa:bb:cc:dd:ee:10") / ARP(op=2, psrc="10.0.0.2", hwsrc="aa:bb:cc:dd:ee:10", pdst="10.0.0.1"),
        1_700_000_002,
    )
    icmp = _stamp(Ether() / IP(src="10.0.0.2", dst="10.0.0.3") / ICMP(), 1_700_000_003)
    return handshake + [dns, arp, icmp]


def horizontal_scan_packets() -> list:
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    packets = []
    for index in range(10):
        packets.append(
            _stamp(
                Ether() / IP(src="10.1.0.5", dst=f"10.1.0.{index + 1}") / TCP(sport=41000 + index, dport=22, flags="S"),
                1_700_000_100 + index,
            )
        )
    return packets


def syn_burst_packets() -> list:
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    return [
        _stamp(
            Ether() / IP(src="10.3.0.5", dst="10.3.0.9") / TCP(sport=50000 + index, dport=80, flags="S"),
            1_700_000_200 + index * 0.01,
        )
        for index in range(20)
    ]


def dns_anomaly_packets() -> list:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    name = ("a" * 40) + ".example.com"
    return [
        _stamp(
            Ether() / IP(src="10.4.0.5", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname=name)),
            1_700_000_300,
        )
    ]


def arp_conflict_packets() -> list:
    from scapy.layers.l2 import ARP, Ether

    first = _stamp(
        Ether(src="aa:bb:cc:dd:ee:01") / ARP(op=2, psrc="10.5.0.9", hwsrc="aa:bb:cc:dd:ee:01", pdst="10.5.0.1"),
        1_700_000_400,
    )
    second = _stamp(
        Ether(src="aa:bb:cc:dd:ee:02") / ARP(op=2, psrc="10.5.0.9", hwsrc="aa:bb:cc:dd:ee:02", pdst="10.5.0.1"),
        1_700_000_401,
    )
    return [first, second]


def write_capture(path: Path, packets: list) -> None:
    from scapy.utils import wrpcap

    wrpcap(str(path), packets)
