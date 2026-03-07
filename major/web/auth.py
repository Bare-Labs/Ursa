"""Web auth and RBAC helpers."""

from fastapi import HTTPException, Request

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
