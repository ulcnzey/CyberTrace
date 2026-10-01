"""Background live capture that feeds the same pipeline as PCAP analysis."""

import logging
import threading
import time

from app.config import settings
from app.core.errors import AnalysisError
from app.core.pipeline import run_pipeline, utcnow
from app.ingestion.live_source import list_interfaces, unavailable_reason
from app.ingestion.normalizer import normalize_packet
from app.persistence.repositories import create_session, mark_session, save_result
from app.services.read_models import analysis_detail, list_alerts

logger = logging.getLogger(__name__)


class LiveMonitor:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._end_reason = "duration"
        self.session_id: int | None = None

    def status(self) -> dict:
        running = self._thread is not None and self._thread.is_alive()
        return {
            "running": running,
            "session_id": self.session_id,
            "message": unavailable_reason(),
        }

    def start(self, interface: str, duration_seconds: int | None) -> dict:
        reason = unavailable_reason()
        if reason:
            raise AnalysisError(reason, status_code=503)
        name = interface.strip()
        if not name:
            raise AnalysisError("Choose a network interface.")
        known = {item["name"] for item in list_interfaces()}
        if name not in known:
            raise AnalysisError("That network interface is not available.")
        duration = duration_seconds or settings.live_default_duration
        duration = max(5, min(int(duration), settings.live_max_duration))
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise AnalysisError("A live capture is already running.", status_code=409)
            session_id = create_session(
                name=f"Live {name}",
                source_type="live",
                source_label=name,
            )
            self.session_id = session_id
            self._stop = threading.Event()
            self._end_reason = "duration"
            self._thread = threading.Thread(
                target=self._run,
                args=(session_id, name, duration, self._stop),
                daemon=True,
                name="cybertrace-live",
            )
            self._thread.start()
        detail = analysis_detail(session_id)
        return detail or {"id": session_id, "status": "running"}

    def stop(self) -> dict:
        with self._lock:
            thread = self._thread
            session_id = self.session_id
            if thread is None or not thread.is_alive():
                return {"running": False, "session_id": session_id}
            self._end_reason = "user"
            self._stop.set()
        thread.join(timeout=15)
        return {"running": thread.is_alive(), "session_id": session_id}

    def _run(self, session_id: int, interface: str, duration: int, stop_event: threading.Event) -> None:
        from app.api.hub import hub

        packets = []
        packet_lock = threading.Lock()
        warning = None

        def _on_packet(raw) -> None:
            nonlocal warning
            with packet_lock:
                if len(packets) >= settings.live_max_packets:
                    warning = (
                        f"Capture stopped after {settings.live_max_packets} packets "
                        "to keep memory bounded."
                    )
                    self._end_reason = "buffer"
                    stop_event.set()
                    return
                try:
                    packets.append(normalize_packet(raw))
                except Exception:
                    logger.debug("skipped a live packet", exc_info=True)

        try:
            from scapy.sendrecv import AsyncSniffer

            sniffer = AsyncSniffer(iface=interface, prn=_on_packet, store=False)
            sniffer.start()
        except Exception:
            logger.exception("live capture failed to start")
            message = (
                "Live capture could not start. Check that Npcap is installed and this "
                "process may open the selected interface."
            )
            mark_session(session_id, status="failed", error_message=message)
            hub.publish(session_id, {"type": "status", "status": "failed", "detail": message})
            return

        hub.publish(session_id, {"type": "status", "status": "running", "detail": "Capture started."})
        deadline = time.time() + duration
        seen_alerts: set[str] = set()
        last_count = -1
        try:
            while time.time() < deadline and not stop_event.is_set():
                time.sleep(1)
                last_count = self._flush(
                    session_id,
                    packets,
                    packet_lock,
                    seen_alerts,
                    last_count,
                    final=False,
                    status="running",
                    warning=warning,
                )
            try:
                sniffer.stop()
            except Exception:
                logger.exception("stopping the live capture failed")
            if self._end_reason == "user":
                final_status = "stopped"
            else:
                final_status = "completed"
            self._flush(
                session_id,
                packets,
                packet_lock,
                seen_alerts,
                -1,
                final=True,
                status=final_status,
                warning=warning,
            )
        except Exception:
            logger.exception("live analysis failed")
            message = "Live analysis stopped because an internal error occurred."
            mark_session(session_id, status="failed", error_message=message)
            hub.publish(session_id, {"type": "status", "status": "failed", "detail": message})
            try:
                sniffer.stop()
            except Exception:
                logger.debug("sniffer was already stopped", exc_info=True)

    def _flush(
        self,
        session_id: int,
        packets: list,
        packet_lock: threading.Lock,
        seen_alerts: set[str],
        last_count: int,
        *,
        final: bool,
        status: str,
        warning: str | None,
    ) -> int:
        from app.api.hub import hub

        with packet_lock:
            snapshot = list(packets)
        if not final and len(snapshot) == last_count:
            return last_count
        result = run_pipeline(
            snapshot,
            started_at=utcnow(),
            ended_at=utcnow() if final else None,
            source_label="live capture",
            warning=warning,
        )
        save_result(session_id, result, status=status if final else "running")
        for alert in (list_alerts(session_id) or {"items": []}).get("items", []):
            marker = "|".join(
                [
                    str(alert.get("detector_id")),
                    str(alert.get("src_ip")),
                    str(alert.get("dst_ip")),
                    str(alert.get("dst_port")),
                    str(alert.get("evidence"))[:80],
                ]
            )
            if marker in seen_alerts:
                continue
            seen_alerts.add(marker)
            hub.publish(session_id, {"type": "detection", "detection": alert})
            hub.publish(session_id, {"type": "alert", "alert": alert})
        hub.publish(
            session_id,
            {
                "type": "stats",
                "status": status if final else "running",
                "packet_count": result.packet_count,
                "byte_count": result.byte_count,
                "protocols": result.protocol_counts,
                "connections": len(result.flows),
                "alerts": len(result.alerts),
                "warning": result.warning,
            },
        )
        if final:
            hub.publish(
                session_id,
                {"type": "status", "status": status, "detail": warning or "Capture finished."},
            )
        return len(snapshot)


live_monitor = LiveMonitor()
