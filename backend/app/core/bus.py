"""
AdaptShield In-Process Event Bus
================================
Provides decoupled publish-subscribe event routing for the backend core,
pipeline events, forensics logger, and the upcoming WebSocket streaming endpoint.
"""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


class EventBus:
    def __init__(self, max_history: int = 1000):
        self.subscribers: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}
        self.async_subscribers: Dict[str, List[Callable[[Dict[str, Any]], Any]]] = {}
        self.history: deque[Dict[str, Any]] = deque(maxlen=max_history)

    def subscribe(self, event_type: str, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Subscribes a synchronous callback to an event type (or '*' for all events)."""
        self.subscribers.setdefault(event_type, []).append(callback)

    def subscribe_async(self, event_type: str, callback: Callable[[Dict[str, Any]], Any]) -> None:
        """Subscribes an asynchronous callback."""
        self.async_subscribers.setdefault(event_type, []).append(callback)

    def publish(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Publishes an event to all registered synchronous and async subscribers."""
        event = {
            **payload,
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }
        self.history.append(event)

        # Notify exact topic and wildcard subscribers
        topics = [event_type]
        if event_type != "*":
            topics.append("*")

        for topic in topics:
            for cb in self.subscribers.get(topic, []):
                try:
                    cb(event)
                except Exception as e:
                    print(f"[EventBus Error] Callback failed on topic '{topic}': {e}")

        for topic in topics:
            for acb in self.async_subscribers.get(topic, []):
                try:
                    if asyncio.iscoroutinefunction(acb):
                        asyncio.create_task(acb(event))
                    else:
                        acb(event)
                except Exception as e:
                    print(f"[EventBus Error] Async callback failed on topic '{topic}': {e}")

        return event

    def get_history(self, limit: int = 100, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns recent published events matching the criteria."""
        events = list(self.history)
        if event_type:
            events = [e for e in events if e["type"] == event_type]
        return events[-limit:]

    def clear(self) -> None:
        """Clears subscriber registries and event history."""
        self.subscribers.clear()
        self.async_subscribers.clear()
        self.history.clear()
