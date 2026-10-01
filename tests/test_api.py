"""HTTP API for upload, results, and reports."""

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from tests.captures import horizontal_scan_packets, write_capture
from tests.support import reset_db


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_db()
        self.client_context = TestClient(app)
        self.client = self.client_context.__enter__()

    def tearDown(self) -> None:
        self.client_context.__exit__(None, None, None)

    def test_health(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["database"], "ok")

    def test_upload_lists_results_and_reports(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            capture = Path(folder) / "scan.pcap"
            write_capture(capture, horizontal_scan_packets())
            with capture.open("rb") as handle:
                response = self.client.post(
                    "/api/analyses/pcap",
                    files={"file": ("scan.pcap", handle, "application/vnd.tcpdump.pcap")},
                )
        self.assertEqual(response.status_code, 201, response.text)
        created = response.json()
        session_id = created["id"]
        self.assertEqual(self.client.get("/api/analyses").json()["items"][0]["id"], session_id)
        self.assertEqual(self.client.get(f"/api/analyses/{session_id}").status_code, 200)
        self.assertGreater(self.client.get(f"/api/analyses/{session_id}/flows").json()["total"], 0)
        self.assertGreater(len(self.client.get(f"/api/analyses/{session_id}/hosts").json()["items"]), 0)
        alerts = self.client.get(f"/api/analyses/{session_id}/alerts").json()["items"]
        self.assertEqual(alerts[0]["detector_id"], "horizontal_port_scan")
        indicator_types = {
            item["indicator_type"]
            for item in self.client.get(f"/api/analyses/{session_id}/iocs").json()["items"]
        }
        self.assertIn("ip", indicator_types)
        timeline_types = [
            item["event_type"]
            for item in self.client.get(f"/api/analyses/{session_id}/timeline").json()["items"]
        ]
        self.assertIn("analysis_started", timeline_types)
        self.assertIn("alert", timeline_types)
        self.assertEqual(timeline_types[0], "analysis_started")
        self.assertEqual(timeline_types[-1], "analysis_completed")
        self.assertEqual(self.client.get("/api/overview").status_code, 200)
        json_report = self.client.get(f"/api/analyses/{session_id}/reports/json")
        self.assertEqual(json_report.status_code, 200)
        self.assertIn("alerts", json_report.json())
        pdf_report = self.client.get(f"/api/analyses/{session_id}/reports/pdf")
        self.assertEqual(pdf_report.status_code, 200)
        self.assertTrue(pdf_report.content.startswith(b"%PDF"))

    def test_invalid_upload_is_rejected(self) -> None:
        response = self.client.post(
            "/api/analyses/pcap",
            files={"file": ("notes.txt", b"this is not a capture", "text/plain")},
        )
        self.assertEqual(response.status_code, 400)

    def test_missing_analysis_is_not_found(self) -> None:
        self.assertEqual(self.client.get("/api/analyses/9999").status_code, 404)


if __name__ == "__main__":
    unittest.main()
