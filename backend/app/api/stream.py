"""
WebSocket Streaming endpoint with batching for high-throughput event delivery.
Message types supported:
- window_scored
- process_update
- escalation
- alert
- containment
- file_damage
- rollback
- scenario_state
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.app.services.system_state import SystemStateManager

logger = logging.getLogger(__name__)
router = APIRouter()


class WebSocketBroadcaster:
    def __init__(self, flush_interval_seconds: float = 0.08, max_batch_size: int = 25):
        self.active_connections: Set[WebSocket] = set()
        self.event_buffer: List[Dict[str, Any]] = []
        self.flush_interval = flush_interval_seconds
        self.max_batch_size = max_batch_size
        self._lock = asyncio.Lock()
        self._batch_task: Optional[asyncio.Task] = None
        self._subscribed = False

    def subscribe_to_bus(self, state: SystemStateManager) -> None:
        if self._subscribed:
            return
        self._subscribed = True

        # Forward all critical event types from pipeline bus to buffer
        event_types = [
            "window_scored",
            "process_update",
            "escalation",
            "alert",
            "containment",
            "file_damage",
            "rollback",
            "scenario_state",
            "panic_switch",
        ]
        for et in event_types:
            state.bus.subscribe(et, lambda evt, event_type=et: self.queue_event(event_type, evt))

    def queue_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        """Called synchronously from pipeline/bus threads."""
        data = payload.get("payload") if (isinstance(payload, dict) and isinstance(payload.get("payload"), dict)) else payload
        wrapped = {
            "type": event_type,
            "data": data,
            "simulated": True,
        }
        self.event_buffer.append(wrapped)

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)

        # Start periodic batch flush task if not running
        if self._batch_task is None or self._batch_task.done():
            self._batch_task = asyncio.create_task(self._periodic_flush_loop())

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self.active_connections.discard(websocket)

    async def broadcast_batch(self, batch: List[Dict[str, Any]]) -> None:
        if not batch or not self.active_connections:
            return

        message_str = json.dumps({
            "type": "batch",
            "count": len(batch),
            "events": batch,
            "simulated": True,
        })

        dead_connections = []
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message_str)
            except Exception:
                dead_connections.append(connection)

        if dead_connections:
            async with self._lock:
                for dead in dead_connections:
                    self.active_connections.discard(dead)

    async def _periodic_flush_loop(self) -> None:
        while True:
            await asyncio.sleep(self.flush_interval)
            if self.event_buffer and self.active_connections:
                # Grab and clear current buffer
                to_send = self.event_buffer[:self.max_batch_size]
                self.event_buffer = self.event_buffer[self.max_batch_size:]
                if to_send:
                    await self.broadcast_batch(to_send)
            elif not self.active_connections and not self.event_buffer:
                # No active connections and buffer empty, sleep a bit longer
                await asyncio.sleep(0.2)


broadcaster = WebSocketBroadcaster()


@router.websocket("/stream")
async def websocket_stream(websocket: WebSocket):
    state = SystemStateManager.get_instance()
    broadcaster.subscribe_to_bus(state)
    await broadcaster.connect(websocket)

    # Send initial connection acknowledgment
    await websocket.send_text(json.dumps({
        "type": "connection_established",
        "data": {
            "mode": state.mode,
            "active_detector": state.pipeline.model_name,
            "policy": state.policy,
            "active_scenario": state.active_scenario.scenario_name if state.active_scenario and state.active_scenario.status == "running" else None,
        },
        "simulated": True,
    }))

    try:
        while True:
            # Keep connection open, handle client ping or messages
            text = await websocket.receive_text()
            try:
                msg = json.loads(text)
                if msg.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong", "simulated": True}))
            except Exception:
                pass
    except WebSocketDisconnect:
        await broadcaster.disconnect(websocket)
    except Exception as e:
        logger.warning(f"WebSocket client error: {e}")
        await broadcaster.disconnect(websocket)
