"""Long or high-entropy DNS names, and unusually large query sets."""

import math
from collections import Counter, defaultdict

from app.core.domain import AnalysisContext, Detection

MIN_LABEL_LENGTH = 40
MIN_ENTROPY_LENGTH = 20
MIN_ENTROPY = 3.7
MIN_UNIQUE_QUERIES = 25


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


class DnsAnomalyDetector:
    detector_id = "dns_anomaly"
    name = "DNS anomaly"

    def analyze(self, context: AnalysisContext) -> list[Detection]:
        findings = []
        reported: set[tuple[str | None, str]] = set()
        names_by_source: dict[str, set[str]] = defaultdict(set)
        first_seen: dict[str, float] = {}
        for query in context.dns_queries:
            if not query.qname:
                continue
            if query.src_ip:
                names_by_source[query.src_ip].add(query.qname)
                previous = first_seen.get(query.src_ip)
                if previous is None or query.timestamp < previous:
                    first_seen[query.src_ip] = query.timestamp
            label = query.qname.split(".", 1)[0]
            long_name = len(label) >= MIN_LABEL_LENGTH
            entropy = _entropy(label)
            high_entropy = len(label) >= MIN_ENTROPY_LENGTH and entropy >= MIN_ENTROPY
            if not long_name and not high_entropy:
                continue
            key = (query.src_ip, query.qname)
            if key in reported:
                continue
            reported.add(key)
            if long_name:
                confidence = min(0.95, 0.6 + (len(label) - MIN_LABEL_LENGTH) / 200)
                measured = f"label length {len(label)} (threshold {MIN_LABEL_LENGTH})"
            else:
                confidence = min(0.95, 0.6 + (entropy - MIN_ENTROPY) / 4)
                measured = f"label entropy {entropy:.2f} (threshold {MIN_ENTROPY})"
            if query.src_ip:
                evidence = f"{query.src_ip} queried DNS name {query.qname}; {measured}."
            elif query.dst_ip:
                evidence = f"DNS name {query.qname} was queried to {query.dst_ip}; {measured}."
            else:
                continue
            findings.append(
                Detection(
                    detector_id=self.detector_id,
                    name=self.name,
                    confidence=confidence,
                    evidence=evidence,
                    recommended_action=(
                        "Confirm the DNS name is expected. Unexpected long or high-entropy "
                        "names should be traced to the requesting host and blocked at the resolver."
                    ),
                    src_ip=query.src_ip,
                    dst_ip=query.dst_ip,
                    dst_port=53,
                    protocol="DNS",
                    timestamp=query.timestamp,
                    domain=query.qname,
                )
            )

        for src_ip, names in names_by_source.items():
            if len(names) < MIN_UNIQUE_QUERIES:
                continue
            confidence = min(0.9, 0.6 + (len(names) - MIN_UNIQUE_QUERIES) / 200)
            findings.append(
                Detection(
                    detector_id=self.detector_id,
                    name=self.name,
                    confidence=confidence,
                    evidence=(
                        f"{src_ip} sent {len(names)} distinct DNS queries "
                        f"(threshold {MIN_UNIQUE_QUERIES})."
                    ),
                    recommended_action=(
                        "Review whether this host should generate that query volume. "
                        "Compare the names with the resolver log for the same window."
                    ),
                    src_ip=src_ip,
                    dst_port=53,
                    protocol="DNS",
                    timestamp=first_seen.get(src_ip),
                )
            )
        return findings
