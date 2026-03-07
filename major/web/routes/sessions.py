"""Session routes — list, detail, task creation, kill."""

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import Response
from major.db import (
    list_sessions, get_session, create_task, get_task,
    kill_session, list_tasks, list_files, get_events,
)
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
    task_id = create_task(session_id, task_type, args)
    task = get_task(task_id)

    return templates.TemplateResponse("partials/task_row.html", {
        "request": request, "task": task,
    })


@router.post("/{session_id}/kill")
async def kill_session_route(request: Request, session_id: str):
    create_task(session_id, "kill")
    kill_session(session_id)

    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/sessions"
    return response
