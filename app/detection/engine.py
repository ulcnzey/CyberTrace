"""Run registered detectors over one analysis context."""

import logging

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
        return findings
