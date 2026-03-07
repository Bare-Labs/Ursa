"""Campaign routes — campaign-centric operational view."""

from fastapi import APIRouter, Request
from fastapi.responses import Response

from major.db import (
    add_campaign_note,
    delete_campaign_note,
    evaluate_campaign_policy_alerts,
    get_campaign_policy,
    get_campaign_timeline,
    get_events,
    list_approval_requests,
    list_campaign_notes,
    list_sessions,
    list_tasks,
)
from major.governance import get_policy_remediation_plan
from major.web.app import templates

router = APIRouter(prefix="/campaigns")


@router.get("/")
async def campaign_list(request: Request):
    sessions = list_sessions()
    tasks = list_tasks(limit=2000)
    events = get_events(limit=2000)
    approvals = list_approval_requests(status="pending", limit=2000)

    campaigns: dict[str, dict[str, int]] = {}
    for s in sessions:
        name = (s.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0, "approvals": 0})
        campaigns[name]["sessions"] += 1
    for t in tasks:
        name = (t.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0, "approvals": 0})
        campaigns[name]["tasks"] += 1
    for e in events:
        name = (e.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0, "approvals": 0})
        campaigns[name]["events"] += 1
    for a in approvals:
        name = (a.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0, "approvals": 0})
        campaigns[name]["approvals"] += 1

    rows = sorted(
        campaigns.items(),
        key=lambda item: (
            item[1]["sessions"] + item[1]["tasks"] + item[1]["events"] + item[1]["approvals"]
        ),
        reverse=True,
    )
    return templates.TemplateResponse(
        "campaigns.html",
        {
            "request": request,
            "active_page": "campaigns",
            "campaigns": rows,
        },
    )


@router.get("/{campaign_name}")
async def campaign_detail(request: Request, campaign_name: str):
    sessions = list_sessions(campaign=campaign_name)
    tasks = list_tasks(campaign=campaign_name, limit=150)
    events = get_events(campaign=campaign_name, limit=150)
    pending_approvals = list_approval_requests(status="pending", campaign=campaign_name, limit=150)
    policy = get_campaign_policy(campaign_name)
    alerts = evaluate_campaign_policy_alerts(campaign=campaign_name)
    recommendations = get_policy_remediation_plan(campaign=campaign_name)
    timeline = get_campaign_timeline(campaign_name, limit=200)
    notes = list_campaign_notes(campaign=campaign_name, limit=200)

    by_status: dict[str, int] = {}
    by_task_type: dict[str, int] = {}
    by_risk: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for s in sessions:
        status = s.get("status", "unknown")
        by_status[status] = by_status.get(status, 0) + 1
    for t in tasks:
        task_type = t.get("task_type", "unknown")
        by_task_type[task_type] = by_task_type.get(task_type, 0) + 1
    for a in pending_approvals:
        risk = (a.get("risk_level") or "").lower()
        if risk in by_risk:
            by_risk[risk] += 1

    return templates.TemplateResponse(
        "campaign_detail.html",
        {
            "request": request,
            "active_page": "campaigns",
            "campaign_name": campaign_name,
            "sessions": sessions,
            "tasks": tasks,
            "events": events,
            "pending_approvals": pending_approvals,
            "policy": policy,
            "alerts": alerts,
            "recommendations": recommendations,
            "timeline": timeline,
            "notes": notes,
            "by_status": by_status,
            "by_task_type": sorted(by_task_type.items(), key=lambda item: item[1], reverse=True)[:8],
            "by_risk": by_risk,
        },
    )


@router.post("/{campaign_name}/notes")
async def campaign_add_note(request: Request, campaign_name: str):
    form = await request.form()
    author = str(form.get("author", "web-ui:operator")).strip() or "web-ui:operator"
    note = str(form.get("note", "")).strip()
    if note:
        add_campaign_note(campaign_name, note, author=author)
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = f"/campaigns/{campaign_name}"
    return response


@router.post("/{campaign_name}/notes/{note_id}/delete")
async def campaign_delete_note(campaign_name: str, note_id: int):
    _ = delete_campaign_note(note_id)
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = f"/campaigns/{campaign_name}"
    return response
