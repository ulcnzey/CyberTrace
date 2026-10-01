"""Report documents include the stored analysis sections."""

import json
import tempfile
import unittest
from pathlib import Path

from app.reporting.reports import json_report_path, pdf_report_path
from app.services.analysis_service import analyze_capture_file
from tests.captures import horizontal_scan_packets, write_capture
from tests.support import reset_db


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_db()

    def test_json_and_pdf_cover_the_required_sections(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "scan.pcap"
            write_capture(path, horizontal_scan_packets())
            detail = analyze_capture_file(path, "scan.pcap")
        document_path = json_report_path(detail["id"])
        document = json.loads(document_path.read_text(encoding="utf-8"))
        for key in ("summary", "traffic_statistics", "hosts", "connections", "alerts", "iocs", "timeline"):
            self.assertIn(key, document)
        self.assertTrue(document["alerts"])
        pdf_path = pdf_report_path(detail["id"])
        self.assertTrue(pdf_path.read_bytes().startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
