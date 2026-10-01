"""Live monitoring uses the shared pipeline and fails honestly without a capture device."""

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.ingestion.live_source import unavailable_reason
from app.main import app
from app.services.analysis_service import analyze_packets
from app.services.read_models import list_alerts
from tests.support import packet, reset_db


class LiveMonitoringTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_db()
        self.client_context = TestClient(app)
        self.client = self.client_context.__enter__()

    def tearDown(self) -> None:
        self.client_context.__exit__(None, None, None)

    def test_same_engine_detects_a_scan_marked_as_live(self) -> None:
        packets = [
            packet(
                src_ip="10.1.0.5",
                dst_ip=f"10.1.0.{index}",
                src_port=41000 + index,
                dst_port=22,
                tcp_flags="S",
                timestamp=100 + index,
            )
            for index in range(1, 11)
        ]
        detail = analyze_packets(packets, name="live-scan", source_type="live", source_label="lab0")
        self.assertEqual(detail["source_type"], "live")
        alerts = (list_alerts(detail["id"]) or {"items": []})["items"]
        self.assertEqual(alerts[0]["detector_id"], "horizontal_port_scan")
        self.assertEqual(alerts[0]["severity"], "high")
        self.assertAlmostEqual(alerts[0]["confidence"], 0.6)

    def test_start_reports_capture_unavailable_instead_of_success(self) -> None:
        with patch("app.services.live_monitor.unavailable_reason", return_value="Npcap is not installed."):
            response = self.client.post(
                "/api/live/start",
                json={"interface": "eth0", "duration_seconds": 30},
            )
        self.assertEqual(response.status_code, 503)
        self.assertIn("Npcap", response.json()["detail"])
        self.assertEqual(self.client.get("/api/analyses").json()["items"], [])

    def test_unavailable_reason_does_not_raise(self) -> None:
        reason = unavailable_reason()
        self.assertTrue(reason is None or isinstance(reason, str))

    def test_websocket_sends_a_connection_status(self) -> None:
        with self.client.websocket_connect("/ws/live/1") as websocket:
            message = websocket.receive_json()
        self.assertEqual(message["type"], "status")
        self.assertEqual(message["status"], "connected")
        self.assertEqual(message["session_id"], 1)

    def test_interfaces_endpoint_is_structured(self) -> None:
        payload = self.client.get("/api/interfaces").json()
        self.assertIn("available", payload)
        self.assertIn("message", payload)
        self.assertIsInstance(payload["interfaces"], list)


if __name__ == "__main__":
    unittest.main()
