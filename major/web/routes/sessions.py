"""Session routes — list, detail, task creation, kill."""

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from major.db import (
    get_events,
    get_session,
    get_task,
    kill_session,
    list_files,
    list_sessions,
    list_tasks,
)
from major.governance import queue_task_with_policy
from major.web.app import templates

router = APIRouter(prefix="/sessions")


@router.get("/")
async def session_list(request: Request, status: str | None = None):
    sessions = list_sessions(status=status)

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse("partials/session_table.html", {
            "request": request, "sessions": sessions,
        })

    return templates.TemplateResponse("sessions.html", {
        "request": request,
        "active_page": "sessions",
        "sessions": sessions,
        "current_status": status,
    })


@router.get("/{session_id}")
async def session_detail(request: Request, session_id: str):
    session = get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")

    return templates.TemplateResponse("session_detail.html", {
        "request": request,
        "active_page": "sessions",
        "session": session,
        "tasks": list_tasks(session_id=session_id, limit=50),
        "files": list_files(session_id=session_id),
        "events": get_events(session_id=session_id, limit=20),
    })


@router.post("/{session_id}/task")
async def create_session_task(request: Request, session_id: str):
    form = await request.form()
    command = form.get("command", "").strip()
    task_type = form.get("task_type", "shell")

    args = {"command": command} if task_type == "shell" and command else {}
    decision = queue_task_with_policy(
        session_id=session_id,
        task_type=task_type,
        args=args,
        actor="web-ui:sessions/task",
    )
    if decision["status"] != "queued":
        approval_id = decision.get("approval_id", "-")
        raise HTTPException(403, f"{decision['message']} (approval_id={approval_id})")
    task_id = decision["task_id"]
    task = get_task(task_id)

    return templates.TemplateResponse("partials/task_row.html", {
        "request": request, "task": task,
    })


@router.post("/{session_id}/kill")
async def kill_session_route(request: Request, session_id: str):
    decision = queue_task_with_policy(
        session_id=session_id,
        task_type="kill",
        args={},
        actor="web-ui:sessions/kill",
    )
    if decision["status"] != "queued":
        approval_id = decision.get("approval_id", "-")
        raise HTTPException(403, f"{decision['message']} (approval_id={approval_id})")
    kill_session(session_id)

    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/sessions"
    return response
