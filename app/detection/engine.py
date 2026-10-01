"""Run registered detectors over one analysis context."""

import logging
import math

from app.core.domain import AnalysisContext, Detection

logger = logging.getLogger(__name__)


class DetectionEngine:
    def __init__(self, detectors: list | None = None):
        if detectors is None:
            from app.detection.registry import default_detectors

            detectors = default_detectors()
        self.detectors = list(detectors)

    def run(self, context: AnalysisContext) -> list[Detection]:
        findings: list[Detection] = []
        for detector in self.detectors:
            try:
                findings.extend(detector.analyze(context))
            except Exception as exc:
                logger.error(
                    "detector %s failed: %s",
                    getattr(detector, "detector_id", detector),
                    exc,
                )
        return [finding for finding in findings if _is_grounded(finding)]


def _is_grounded(finding: Detection) -> bool:
    """Keep a finding only when it cites observed traffic and a real confidence."""
    if not finding.evidence.strip():
        return False
    if not math.isfinite(finding.confidence) or not 0 <= finding.confidence <= 1:
        return False
    observed = any(
        (
            finding.src_ip,
            finding.dst_ip,
            finding.domain,
            finding.url,
            finding.macs,
            finding.dst_port is not None,
            finding.src_port is not None,
        )
    )
    return observed
