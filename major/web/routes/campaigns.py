"""Campaign routes — campaign-centric operational view."""

import json
from datetime import datetime
from urllib.parse import urlencode

from fastapi import APIRouter, Request
from fastapi.responses import Response

from major.db import (
    add_campaign_checklist_item,
    add_campaign_note,
    delete_campaign_checklist_item,
    delete_campaign_note,
    evaluate_campaign_policy_alerts,
    get_campaign_policy,
    get_campaign_timeline,
    get_events,
    list_approval_requests,
    list_campaign_checklist,
    list_campaign_notes,
    list_sessions,
    list_tasks,
    update_campaign_checklist_item,
)
from major.governance import get_policy_remediation_plan
from major.web.app import templates

router = APIRouter(prefix="/campaigns")
CHECKLIST_STATUSES = {"pending", "in_progress", "blocked", "done"}
CHECKLIST_SORT_OPTIONS = {"created_desc", "created_asc", "updated_desc", "updated_asc", "due_asc", "due_desc"}


def _parse_due_at(value: str) -> float | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def _campaign_redirect(campaign_name: str, status: str = "", owner: str = "", q: str = "", sort: str = "") -> str:
    params: dict[str, str] = {}
    if status:
        params["status"] = status
    if owner:
        params["owner"] = owner
    if q:
        params["q"] = q
    if sort:
        params["sort"] = sort
    if params:
        return f"/campaigns/{campaign_name}?" + urlencode(params)
    return f"/campaigns/{campaign_name}"


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
    status_filter = str(request.query_params.get("status", "")).strip().lower()
    owner_filter = str(request.query_params.get("owner", "")).strip()
    text_filter = str(request.query_params.get("q", "")).strip()
    sort = str(request.query_params.get("sort", "created_desc")).strip().lower()
    if status_filter and status_filter not in CHECKLIST_STATUSES:
        status_filter = ""
    if sort not in CHECKLIST_SORT_OPTIONS:
        sort = "created_desc"

    sessions = list_sessions(campaign=campaign_name)
    tasks = list_tasks(campaign=campaign_name, limit=150)
    events = get_events(campaign=campaign_name, limit=150)
    pending_approvals = list_approval_requests(status="pending", campaign=campaign_name, limit=150)
    policy = get_campaign_policy(campaign_name)
    alerts = evaluate_campaign_policy_alerts(campaign=campaign_name)
    recommendations = get_policy_remediation_plan(campaign=campaign_name)
    timeline = get_campaign_timeline(campaign_name, limit=200)
    notes = list_campaign_notes(campaign=campaign_name, limit=200)
    checklist_items = list_campaign_checklist(
        campaign=campaign_name,
        status=status_filter or None,
        owner=owner_filter or None,
        text=text_filter or None,
        sort=sort,
        limit=300,
    )
    checklist_all = list_campaign_checklist(campaign=campaign_name, limit=1000)
    checklist_counts = {"pending": 0, "in_progress": 0, "blocked": 0, "done": 0}
    for item in checklist_all:
        st = (item.get("status") or "pending").strip().lower()
        if st not in checklist_counts:
            st = "pending"
        checklist_counts[st] += 1

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
            "checklist_items": checklist_items,
            "checklist_counts": checklist_counts,
            "checklist_filters": {
                "status": status_filter,
                "owner": owner_filter,
                "q": text_filter,
                "sort": sort,
            },
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


@router.post("/{campaign_name}/checklist")
async def campaign_add_checklist_item(request: Request, campaign_name: str):
    form = await request.form()
    title = str(form.get("title", "")).strip()
    details = str(form.get("details", "")).strip()
    owner = str(form.get("owner", "")).strip()
    due_at = _parse_due_at(str(form.get("due_at", "")))
    status_filter = str(form.get("status_filter", "")).strip().lower()
    owner_filter = str(form.get("owner_filter", "")).strip()
    text_filter = str(form.get("q_filter", "")).strip()
    sort = str(form.get("sort_filter", "created_desc")).strip().lower()
    if title:
        add_campaign_checklist_item(
            campaign=campaign_name,
            title=title,
            details=details,
            owner=owner,
            due_at=due_at,
        )
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = _campaign_redirect(
        campaign_name,
        status=status_filter,
        owner=owner_filter,
        q=text_filter,
        sort=sort,
    )
    return response


@router.post("/{campaign_name}/checklist/{item_id}/update")
async def campaign_update_checklist_item(request: Request, campaign_name: str, item_id: int):
    form = await request.form()
    status_filter = str(form.get("status_filter", "")).strip().lower()
    owner_filter = str(form.get("owner_filter", "")).strip()
    text_filter = str(form.get("q_filter", "")).strip()
    sort_filter = str(form.get("sort_filter", "created_desc")).strip().lower()
    status = str(form.get("status", "")).strip().lower()
    updates = {}
    if status in CHECKLIST_STATUSES:
        updates["status"] = status
    title = str(form.get("title", "")).strip()
    if title:
        updates["title"] = title
    details = str(form.get("details", "")).strip()
    if details:
        updates["details"] = details
    owner = str(form.get("owner", "")).strip()
    if owner:
        updates["owner"] = owner
    if "due_at" in form:
        updates["due_at"] = _parse_due_at(str(form.get("due_at", "")))
    if updates:
        update_campaign_checklist_item(item_id, **updates)
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = _campaign_redirect(
        campaign_name,
        status=status_filter,
        owner=owner_filter,
        q=text_filter,
        sort=sort_filter,
    )
    return response


@router.post("/{campaign_name}/checklist/{item_id}/delete")
async def campaign_delete_checklist_item(request: Request, campaign_name: str, item_id: int):
    form = await request.form()
    status_filter = str(form.get("status_filter", "")).strip().lower()
    owner_filter = str(form.get("owner_filter", "")).strip()
    text_filter = str(form.get("q_filter", "")).strip()
    sort_filter = str(form.get("sort_filter", "created_desc")).strip().lower()
    _ = delete_campaign_checklist_item(item_id)
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = _campaign_redirect(
        campaign_name,
        status=status_filter,
        owner=owner_filter,
        q=text_filter,
        sort=sort_filter,
    )
    return response


@router.post("/{campaign_name}/checklist/bulk")
async def campaign_bulk_update_checklist(request: Request, campaign_name: str):
    form = await request.form()
    action_status = str(form.get("action_status", "")).strip().lower()
    status_filter = str(form.get("status_filter", "")).strip().lower()
    owner_filter = str(form.get("owner_filter", "")).strip()
    text_filter = str(form.get("q_filter", "")).strip()
    sort_filter = str(form.get("sort_filter", "created_desc")).strip().lower()
    if action_status in CHECKLIST_STATUSES:
        rows = list_campaign_checklist(
            campaign=campaign_name,
            status=status_filter or None,
            owner=owner_filter or None,
            text=text_filter or None,
            sort=sort_filter,
            limit=1000,
        )
        for row in rows:
            update_campaign_checklist_item(int(row["id"]), status=action_status)
    response = Response(status_code=200)
    response.headers["HX-Redirect"] = _campaign_redirect(
        campaign_name,
        status=status_filter,
        owner=owner_filter,
        q=text_filter,
        sort=sort_filter,
    )
    return response


@router.get("/{campaign_name}/handoff")
async def campaign_handoff_report(campaign_name: str, format: str = "md"):
    sessions = list_sessions(campaign=campaign_name)
    tasks = list_tasks(campaign=campaign_name, limit=300)
    events = get_events(campaign=campaign_name, limit=300)
    approvals = list_approval_requests(status="pending", campaign=campaign_name, limit=300)
    notes = list_campaign_notes(campaign=campaign_name, limit=100)
    checklist = list_campaign_checklist(campaign=campaign_name, limit=400)
    alerts = evaluate_campaign_policy_alerts(campaign=campaign_name)
    checklist_open = [c for c in checklist if c.get("status") != "done"]

    by_status: dict[str, int] = {}
    for s in sessions:
        status = s.get("status", "unknown")
        by_status[status] = by_status.get(status, 0) + 1

    payload = {
        "campaign": campaign_name,
        "counts": {
            "sessions": len(sessions),
            "tasks": len(tasks),
            "events": len(events),
            "pending_approvals": len(approvals),
            "policy_alerts": len(alerts),
            "notes": len(notes),
            "checklist_items": len(checklist),
            "checklist_open": len(checklist_open),
        },
        "session_status": by_status,
        "pending_approvals": approvals[:10],
        "alerts": alerts[:10],
        "notes": notes[:20],
        "checklist": checklist[:30],
    }

    fmt = format.strip().lower()
    if fmt == "json":
        body = json.dumps(payload, indent=2)
        filename = f"campaign_handoff_{campaign_name}.json"
        content_type = "application/json"
    elif fmt == "md":
        lines = [
            f"# Campaign Handoff: {campaign_name}",
            "",
            "## Summary",
            f"- Sessions: {payload['counts']['sessions']}",
            f"- Tasks (recent): {payload['counts']['tasks']}",
            f"- Events (recent): {payload['counts']['events']}",
            f"- Pending approvals: {payload['counts']['pending_approvals']}",
            f"- Policy alerts: {payload['counts']['policy_alerts']}",
            f"- Notes: {payload['counts']['notes']}",
            f"- Checklist items: {payload['counts']['checklist_items']}",
            f"- Open checklist: {payload['counts']['checklist_open']}",
            "",
            "## Session Status",
        ]
        for key, count in sorted(by_status.items()):
            lines.append(f"- {key}: {count}")
        lines.extend(["", "## Pending Approvals"])
        for a in approvals[:10]:
            lines.append(
                f"- `{a['id']}` risk={a['risk_level']} action={a['action']} session={a.get('session_id') or '-'}"
            )
        lines.extend(["", "## Active Alerts"])
        for a in alerts[:10]:
            lines.append(f"- {a['metric']}: {a['value']} > {a['threshold']} ({a['severity']})")
        lines.extend(["", "## Notes"])
        for n in notes[:20]:
            lines.append(
                f"- [{datetime.fromtimestamp(n['created_at']).strftime('%Y-%m-%d %H:%M:%S')}] "
                f"**{n['author']}**: {n['note']}"
            )
        lines.extend(["", "## Checklist"])
        if checklist:
            for item in checklist[:30]:
                due = "-"
                if item.get("due_at"):
                    due = datetime.fromtimestamp(item["due_at"]).strftime("%Y-%m-%d %H:%M:%S")
                lines.append(
                    f"- `{item['id']}` [{item['status']}] {item['title']} "
                    f"(owner={item.get('owner') or '-'}, due={due})"
                )
        else:
            lines.append("- None")
        lines.append("")
        body = "\n".join(lines)
        filename = f"campaign_handoff_{campaign_name}.md"
        content_type = "text/markdown"
    else:
        return Response(content="format must be md or json", status_code=400)

    response = Response(content=body, media_type=content_type)
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response
