"""Ursa Major — Web UI Application."""

import json
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from major.config import get_config
from major.db import get_user_by_id

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

WEB_DIR = Path(__file__).parent

app = FastAPI(title="Ursa Major C2", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")

session_secret = str(get_config().get("major.web.auth.session_secret", "ursa-dev-session-secret"))

templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))


# -- Template Filters --

def format_timestamp(ts):
    if not ts:
        return "never"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def time_ago(ts):
    if not ts:
        return "never"
    diff = time.time() - ts
    if diff < 60:
        return f"{int(diff)}s ago"
    elif diff < 3600:
        return f"{int(diff // 60)}m ago"
    elif diff < 86400:
        return f"{int(diff // 3600)}h ago"
    else:
        return f"{int(diff // 86400)}d ago"


def status_color(status):
    return {
        "active": "status-active",
        "stale": "status-stale",
        "dead": "status-dead",
        "pending": "status-pending",
        "in_progress": "status-in_progress",
        "completed": "status-completed",
        "error": "status-error",
    }.get(status, "")


def parse_json(val):
    if not val:
        return {}
    if isinstance(val, dict):
        return val
    try:
        return json.loads(val)
    except (json.JSONDecodeError, TypeError):
        return {}


def filesizeformat(size):
    if not size:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


templates.env.filters["format_ts"] = format_timestamp
templates.env.filters["time_ago"] = time_ago
templates.env.filters["status_color"] = status_color
templates.env.filters["parse_json"] = parse_json
templates.env.filters["filesizeformat"] = filesizeformat


# -- Register Routers --

from major.web.routes import (  # noqa: E402
    auth,
    campaigns,
    dashboard,
    events,
    files,
    governance,
    sessions,
    sse,
    tasks,
)


@app.middleware("http")
async def auth_middleware(request, call_next):
    path = request.url.path
    request.state.user = None
    public_paths = {"/auth/login"}
    if path.startswith("/static") or path in public_paths:
        return await call_next(request)

    user = None
    user_id = request.session.get("user_id")
    if user_id:
        user = get_user_by_id(user_id)
        if user and user.get("is_active"):
            request.state.user = user
        else:
            request.session.clear()

    if not user:
        next_path = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        login_url = f"/auth/login?next={quote(next_path, safe='')}"
        if request.headers.get("HX-Request"):
            response = Response(status_code=401)
            response.headers["HX-Redirect"] = login_url
            return response
        return RedirectResponse(url=login_url, status_code=303)
    return await call_next(request)


# SessionMiddleware must be added AFTER @app.middleware("http") so it is
# inserted outermost in the stack and processes request.session before
# auth_middleware runs.
app.add_middleware(
    SessionMiddleware,
    secret_key=session_secret,
    session_cookie="ursa_web_session",
    same_site="lax",
    https_only=False,
)

app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(campaigns.router)
app.include_router(sessions.router)
app.include_router(tasks.router)
app.include_router(files.router)
app.include_router(events.router)
app.include_router(governance.router)
app.include_router(sse.router)
