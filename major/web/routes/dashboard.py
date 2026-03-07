"""Dashboard route — overview of C2 status."""

from fastapi import APIRouter, Request

from major.db import get_events, list_approval_requests, list_sessions, list_tasks
from major.web.app import templates

router = APIRouter()


@router.get("/")
async def dashboard(request: Request):
    sessions = list_sessions()
    active = [s for s in sessions if s["status"] == "active"]
    stale = [s for s in sessions if s["status"] == "stale"]
    dead = [s for s in sessions if s["status"] == "dead"]
    pending_approvals = list_approval_requests(status="pending", limit=500)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "active_page": "dashboard",
        "active_count": len(active),
        "stale_count": len(stale),
        "dead_count": len(dead),
        "total_sessions": len(sessions),
        "pending_approvals": len(pending_approvals),
        "recent_events": get_events(limit=15),
        "recent_tasks": list_tasks(limit=10),
        "active_sessions": active[:5],
    })
