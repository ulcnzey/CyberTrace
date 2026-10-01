"""Read PCAP and PCAPNG files into normalized packets."""

from pathlib import Path

from app.config import settings
from app.core.domain import NormalizedPacket
from app.core.errors import AnalysisError
from app.ingestion.normalizer import normalize_packet

_CAPTURE_SIGNATURES = (
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
)


def looks_like_capture(data: bytes) -> bool:
    return data.startswith(_CAPTURE_SIGNATURES)


def load_capture(path: Path) -> tuple[list[NormalizedPacket], str | None]:
    from scapy.utils import PcapReader

    packets: list[NormalizedPacket] = []
    skipped = 0
    warning = None
    try:
        reader = PcapReader(str(path))
    except Exception as exc:
        raise AnalysisError("The capture could not be read.") from exc
    try:
        for raw in reader:
            try:
                packets.append(normalize_packet(raw))
            except Exception:
                skipped += 1
                continue
            if len(packets) >= settings.max_packets:
                warning = f"Only the first {settings.max_packets} packets were analyzed."
                break
    except AnalysisError:
        raise
    except Exception as exc:
        raise AnalysisError("The capture could not be read.") from exc
    finally:
        reader.close()
    if skipped and warning is None:
        warning = f"{skipped} packets could not be normalized and were skipped."
    elif skipped and warning:
        warning = f"{warning} {skipped} additional packets were skipped."
    return packets, warning
