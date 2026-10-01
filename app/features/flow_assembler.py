"""Group normalized packets into flow summaries."""

from app.core.domain import FlowRecord, NormalizedPacket

_FLOW_PROTOCOLS = {"TCP", "UDP", "ICMP", "ARP"}


def assemble_flows(packets: list[NormalizedPacket]) -> list[FlowRecord]:
    flows: dict[tuple, FlowRecord] = {}
    for packet in packets:
        if packet.protocol not in _FLOW_PROTOCOLS or not packet.src_ip or not packet.dst_ip:
            continue
        mac_key = packet.src_mac if packet.protocol == "ARP" else ""
        key = (
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            packet.protocol,
            mac_key,
        )
        flow = flows.get(key)
        if flow is None:
            flow = FlowRecord(
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                src_mac=packet.src_mac,
                dst_mac=packet.dst_mac,
                packet_count=0,
                byte_count=0,
                started_at=packet.timestamp,
                ended_at=packet.timestamp,
            )
            flows[key] = flow
        flow.packet_count += 1
        flow.byte_count += packet.length
        flow.ended_at = packet.timestamp
        if packet.dst_mac and flow.dst_mac is None:
            flow.dst_mac = packet.dst_mac
        if packet.protocol == "TCP" and packet.tcp_flags:
            flags = packet.tcp_flags
            if "S" in flags and "A" not in flags:
                flow.syn_count += 1
            if "A" in flags:
                flow.ack_count += 1
            if "R" in flags:
                flow.rst_count += 1
    return list(flows.values())
