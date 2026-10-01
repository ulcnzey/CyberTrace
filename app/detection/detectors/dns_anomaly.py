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
        per_source: dict[str | None, set[str]] = defaultdict(set)
        for query in context.dns_queries:
            per_source[query.src_ip].add(query.qname)
            label = query.qname.split(".", 1)[0]
            long_name = len(label) >= MIN_LABEL_LENGTH
            high_entropy = len(label) >= MIN_ENTROPY_LENGTH and _entropy(label) >= MIN_ENTROPY
            if not long_name and not high_entropy:
                continue
            key = (query.src_ip, query.qname)
            if key in reported:
                continue
            reported.add(key)
            reason = "very long" if long_name else "high-entropy"
            confidence = 0.84 if long_name else 0.72
            findings.append(
                Detection(
                    detector_id=self.detector_id,
                    name=self.name,
                    confidence=confidence,
                    evidence=f"{query.src_ip or 'A host'} queried {reason} DNS name {query.qname}.",
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

        for src_ip, names in per_source.items():
            if len(names) < MIN_UNIQUE_QUERIES:
                continue
            confidence = min(0.9, 0.6 + len(names) / 200)
            findings.append(
                Detection(
                    detector_id=self.detector_id,
                    name=self.name,
                    confidence=confidence,
                    evidence=f"{src_ip or 'A host'} sent {len(names)} distinct DNS queries.",
                    recommended_action=(
                        "Review whether this host should generate that query volume. "
                        "Compare the names with the resolver log for the same window."
                    ),
                    src_ip=src_ip,
                    dst_port=53,
                    protocol="DNS",
                    timestamp=None,
                )
            )
        return findings
