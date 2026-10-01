"""Session statistics derived from normalized packets."""

from collections import Counter

from app.core.domain import NormalizedPacket


def traffic_statistics(
    packets: list[NormalizedPacket],
) -> tuple[dict[str, int], list[dict], int, int]:
    counts: Counter[str] = Counter()
    byte_count = 0
    for packet in packets:
        if packet.dns_query:
            name = "DNS"
        else:
            name = packet.protocol
        counts[name] += 1
        byte_count += packet.length

    buckets = _buckets(packets)
    return dict(counts), buckets, len(packets), byte_count


def _buckets(packets: list[NormalizedPacket]) -> list[dict]:
    bucket_count = 12
    packets_per_bucket = [0] * bucket_count
    bytes_per_bucket = [0] * bucket_count
    if not packets:
        return []
    start = min(packet.timestamp for packet in packets)
    end = max(packet.timestamp for packet in packets)
    span = end - start
    for packet in packets:
        if span <= 0:
            index = 0
        else:
            index = min(bucket_count - 1, int((packet.timestamp - start) / span * bucket_count))
        packets_per_bucket[index] += 1
        bytes_per_bucket[index] += packet.length
    width = span / bucket_count if span > 0 else 0
    return [
        {
            "offset_seconds": round(index * width, 3),
            "packets": packets_per_bucket[index],
            "bytes": bytes_per_bucket[index],
        }
        for index in range(bucket_count)
        if packets_per_bucket[index] or bytes_per_bucket[index]
    ]
