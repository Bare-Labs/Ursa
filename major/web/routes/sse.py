"""Server-Sent Events stream for real-time updates."""

import asyncio
import json
import time

from fastapi import APIRouter
from sse_starlette.sse import EventSourceResponse
from major.db import get_events, list_sessions

router = APIRouter()


@router.get("/sse/events")
async def sse_event_stream():
    async def generate():
        last_event_id = None
        last_session_hash = None

        # Get initial state
        events = get_events(limit=1)
        if events:
            last_event_id = events[0]["id"]

        while True:
            await asyncio.sleep(2)

            # Check for new events
            events = get_events(limit=5)
            for e in events:
                if last_event_id and e["id"] <= last_event_id:
                    break
                yield {
                    "event": "new-event",
                    "data": json.dumps({
                        "level": e["level"],
                        "source": e["source"],
                        "message": e["message"],
                        "session_id": e.get("session_id", ""),
                    }),
                }

            if events:
                last_event_id = events[0]["id"]

            # Check for session changes
            sessions = list_sessions()
            session_hash = hash(tuple(
                (s["id"], s["status"]) for s in sessions
            ))
            if session_hash != last_session_hash:
                last_session_hash = session_hash
                yield {
                    "event": "session-update",
                    "data": json.dumps({
                        "active": len([s for s in sessions if s["status"] == "active"]),
                        "stale": len([s for s in sessions if s["status"] == "stale"]),
                        "dead": len([s for s in sessions if s["status"] == "dead"]),
                    }),
                }

    return EventSourceResponse(generate())
