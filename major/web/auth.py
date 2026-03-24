"""Web and API auth / RBAC helpers."""

from fastapi import Header, HTTPException, Request

from major.config import get_config

ROLE_LEVELS = {
    "operator": 1,
    "reviewer": 2,
    "admin": 3,
}


def role_allows(user_role: str, required_role: str) -> bool:
    """Whether role meets or exceeds required role."""
    return ROLE_LEVELS.get((user_role or "").strip().lower(), 0) >= ROLE_LEVELS.get(
        (required_role or "").strip().lower(),
        99,
    )


def current_user(request: Request) -> dict:
    """Current authenticated user from request state."""
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Authentication required")
    return user


def require_role(request: Request, role: str) -> dict:
    """Require minimum role for a route/action."""
    user = current_user(request)
    if not role_allows(user.get("role", ""), role):
        raise HTTPException(403, "Insufficient permissions")
    return user


def actor_for(request: Request, action: str) -> str:
    """Stable actor string for audit records."""
    user = current_user(request)
    return f"web:{user.get('username', 'unknown')}:{action}"


def api_actor_for(user: dict, action: str) -> str:
    """Stable actor string for API-originated audit records."""
    return f"api:{user.get('username', 'unknown')}:{action}"


def require_api_role(
    authorization: str | None = Header(default=None),
    x_bearclaw_actor: str | None = Header(default=None),
    x_bearclaw_role: str | None = Header(default=None),
    role: str = "admin",
) -> dict:
    """Authenticate a bearer-token API request and require minimum role."""
    expected = str(get_config().get("major.web.auth.api_token", "")).strip()
    if not expected:
        raise HTTPException(503, "API token is not configured")

    token = ""
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer":
            token = value.strip()
    if token != expected:
        raise HTTPException(401, "Invalid API token")

    actor = (x_bearclaw_actor or "bearclaw-web").strip()
    actor = "".join(ch if ch.isalnum() or ch in "@._:-" else "-" for ch in actor) or "bearclaw-web"
    user_role = (x_bearclaw_role or "admin").strip().lower()
    if user_role not in ROLE_LEVELS:
        user_role = "admin"
    if not role_allows(user_role, role):
        raise HTTPException(403, "Insufficient permissions")

    return {
        "username": actor,
        "role": user_role,
        "is_active": True,
    }
