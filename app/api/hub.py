"""In-process fan-out for live WebSocket clients."""

import asyncio
import logging
import threading
from collections import defaultdict

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class EventHub:
    def __init__(self) -> None:
        self.loop: asyncio.AbstractEventLoop | None = None
        self._clients: dict[int, set[WebSocket]] = defaultdict(set)
        self._lock = threading.Lock()

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop

    async def connect(self, session_id: int, websocket: WebSocket) -> None:
        await websocket.accept()
        with self._lock:
            self._clients[session_id].add(websocket)
        await websocket.send_json(
            {"type": "status", "status": "connected", "session_id": session_id}
        )

    def disconnect(self, session_id: int, websocket: WebSocket) -> None:
        with self._lock:
            self._clients[session_id].discard(websocket)

    def publish(self, session_id: int, message: dict) -> None:
        loop = self.loop
        if loop is None or not loop.is_running():
            return
        asyncio.run_coroutine_threadsafe(self._send(session_id, message), loop)

    async def _send(self, session_id: int, message: dict) -> None:
        with self._lock:
            clients = list(self._clients.get(session_id, ()))
        stale: list[WebSocket] = []
        for websocket in clients:
            try:
                await websocket.send_json(message)
            except Exception:
                logger.debug("dropping a live client", exc_info=True)
                stale.append(websocket)
        if stale:
            with self._lock:
                for websocket in stale:
                    self._clients[session_id].discard(websocket)


hub = EventHub()
