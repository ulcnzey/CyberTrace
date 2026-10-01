"""Convert Scapy packets into the shared normalized representation."""

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from app.core.domain import NormalizedPacket

_HTTP_METHODS = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"}


def normalize_packet(packet) -> NormalizedPacket:
    timestamp = float(getattr(packet, "time", 0.0) or 0.0)
    length = len(packet)
    src_mac = dst_mac = None
    if packet.haslayer(Ether):
        src_mac = str(packet[Ether].src).lower()
        dst_mac = str(packet[Ether].dst).lower()

    src_ip = dst_ip = None
    protocol = "OTHER"
    src_port = dst_port = None
    tcp_flags = None
    icmp_type = None
    icmp_payload_len = 0
    arp_op = arp_psrc = arp_hwsrc = None

    if packet.haslayer(ARP):
        arp = packet[ARP]
        protocol = "ARP"
        arp_psrc = str(arp.psrc)
        arp_hwsrc = str(arp.hwsrc).lower()
        src_ip = arp_psrc
        dst_ip = str(arp.pdst)
        arp_op = "reply" if int(arp.op) == 2 else "request"
    elif packet.haslayer(IP) or packet.haslayer(IPv6):
        network = packet[IP] if packet.haslayer(IP) else packet[IPv6]
        src_ip = str(network.src)
        dst_ip = str(network.dst)
        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
            tcp_flags = str(packet[TCP].flags)
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            icmp_type = int(packet[ICMP].type)
            icmp_payload_len = len(bytes(packet[ICMP].payload))

    dns_query = _dns_query(packet)
    http_method = http_host = http_path = http_user_agent = None
    if packet.haslayer(Raw) and (dst_port == 80 or src_port == 80):
        parsed = _http_request(bytes(packet[Raw].load))
        if parsed is not None:
            http_method, http_path, http_host, http_user_agent = parsed

    return NormalizedPacket(
        timestamp=timestamp,
        length=length,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_mac=src_mac,
        dst_mac=dst_mac,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        tcp_flags=tcp_flags,
        dns_query=dns_query,
        http_host=http_host,
        http_path=http_path,
        http_user_agent=http_user_agent,
        http_method=http_method,
        icmp_type=icmp_type,
        icmp_payload_len=icmp_payload_len,
        arp_op=arp_op,
        arp_psrc=arp_psrc,
        arp_hwsrc=arp_hwsrc,
    )


def _dns_query(packet) -> str | None:
    if not packet.haslayer(DNS):
        return None
    dns = packet[DNS]
    records = dns.qd
    if not records:
        return None
    record = records[0]
    qname = record.qname
    if isinstance(qname, bytes):
        text = qname.decode("utf-8", errors="ignore")
    else:
        text = str(qname)
    text = text.strip(".").lower()
    return text or None


def _http_request(payload: bytes) -> tuple[str, str, str | None, str | None] | None:
    """Read the request line, Host, and User-Agent. The body is discarded."""
    text = payload[:8192].decode("iso-8859-1", errors="ignore")
    lines = text.split("\r\n")
    if not lines:
        return None
    parts = lines[0].split(" ")
    if len(parts) < 2 or parts[0] not in _HTTP_METHODS:
        return None
    host = None
    user_agent = None
    for line in lines[1:]:
        if line == "":
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        lowered = key.strip().lower()
        if lowered == "host":
            host = value.strip()[:255] or None
        elif lowered == "user-agent":
            user_agent = value.strip()[:255] or None
    return parts[0], parts[1][:512], host, user_agent
