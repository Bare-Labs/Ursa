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
    recent_tasks = list_tasks(limit=200)
    recent_events = get_events(limit=200)

    campaigns: dict[str, dict[str, int]] = {}
    for s in sessions:
        name = (s.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0})
        campaigns[name]["sessions"] += 1
    for t in recent_tasks:
        name = (t.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0})
        campaigns[name]["tasks"] += 1
    for e in recent_events:
        name = (e.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0})
        campaigns[name]["events"] += 1
    top_campaigns = sorted(
        campaigns.items(),
        key=lambda item: item[1]["sessions"] + item[1]["tasks"] + item[1]["events"],
        reverse=True,
    )[:6]
    pending_by_risk: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    pending_by_campaign: dict[str, int] = {}
    for approval in pending_approvals:
        risk = (approval.get("risk_level") or "").lower()
        if risk in pending_by_risk:
            pending_by_risk[risk] += 1
        campaign = (approval.get("campaign") or "unassigned").strip() or "unassigned"
        pending_by_campaign[campaign] = pending_by_campaign.get(campaign, 0) + 1
    top_pending_campaigns = sorted(
        pending_by_campaign.items(),
        key=lambda item: item[1],
        reverse=True,
    )[:6]

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "active_page": "dashboard",
        "active_count": len(active),
        "stale_count": len(stale),
        "dead_count": len(dead),
        "total_sessions": len(sessions),
        "pending_approvals": len(pending_approvals),
        "recent_events": recent_events[:15],
        "recent_tasks": recent_tasks[:10],
        "active_sessions": active[:5],
        "top_campaigns": top_campaigns,
        "pending_by_risk": pending_by_risk,
        "top_pending_campaigns": top_pending_campaigns,
    })
