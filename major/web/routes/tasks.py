"""Task routes — global task list and detail."""

from fastapi import APIRouter, Request, HTTPException
from major.db import list_tasks, get_task
from major.web.app import templates

router = APIRouter(prefix="/tasks")


@router.get("/")
async def task_list(
    request: Request,
    session_id: str | None = None,
    status: str | None = None,
):
    tasks = list_tasks(session_id=session_id, status=status, limit=100)

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse("partials/task_table.html", {
            "request": request, "tasks": tasks,
        })

    return templates.TemplateResponse("tasks.html", {
        "request": request,
        "active_page": "tasks",
        "tasks": tasks,
        "current_session": session_id,
        "current_status": status,
    })


@router.get("/{task_id}")
async def task_detail(request: Request, task_id: str):
    task = get_task(task_id)
    if not task:
        raise HTTPException(404, "Task not found")

    return templates.TemplateResponse("partials/shell_output.html", {
        "request": request, "task": task,
    })
