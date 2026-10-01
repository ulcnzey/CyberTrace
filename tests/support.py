"""Shared fixtures for the CyberTrace test suite."""

from pathlib import Path

from app.core.domain import NormalizedPacket
from app.features.extractors import build_context  # noqa: E402
from app.features.flow_assembler import assemble_flows  # noqa: E402
from app.persistence.database import engine, init_db  # noqa: E402
from app.persistence.orm import Base  # noqa: E402


def reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    init_db()


def packet(**overrides) -> NormalizedPacket:
    values = {
        "timestamp": 1_700_000_000.0,
        "length": 60,
        "src_ip": "10.0.0.2",
        "dst_ip": "10.0.0.3",
        "src_port": 40000,
        "dst_port": 80,
        "protocol": "TCP",
        "tcp_flags": "A",
    }
    values.update(overrides)
    return NormalizedPacket(**values)


def context_from(packets: list[NormalizedPacket]):
    flows = assemble_flows(packets)
    return build_context(packets, flows), flows


def write_pcap(path: Path, scapy_packets: list) -> None:
    from scapy.utils import wrpcap

    wrpcap(str(path), scapy_packets)
