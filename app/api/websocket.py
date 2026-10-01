"""WebSocket stream for one live analysis session."""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.api.hub import hub

router = APIRouter(tags=["live"])


@router.websocket("/ws/live/{session_id}")
async def live_stream(websocket: WebSocket, session_id: int) -> None:
    await hub.connect(session_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        hub.disconnect(session_id, websocket)
