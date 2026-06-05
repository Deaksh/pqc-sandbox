"""
Role-Based Access Control (RBAC) — stub implementation.
In production: integrate with your auth provider or internal user service.
"""
from __future__ import annotations

from functools import wraps
from typing import Callable

from qs_platform.api.models import UserRole


# Permission matrix: role → set of allowed actions
_PERMISSIONS: dict[UserRole, set[str]] = {
    UserRole.OWNER: {
        "org.manage", "org.billing", "org.delete",
        "users.invite", "users.remove", "users.role",
        "assets.*", "scans.*", "reports.*", "alerts.*",
        "sso.configure", "audit.read",
    },
    UserRole.ADMIN: {
        "users.invite", "users.remove",
        "assets.*", "scans.*", "reports.*", "alerts.*",
        "audit.read",
    },
    UserRole.ANALYST: {
        "assets.read", "assets.create", "assets.scan",
        "scans.read", "scans.create",
        "reports.read", "reports.create",
        "alerts.read", "alerts.acknowledge",
    },
    UserRole.VIEWER: {
        "assets.read", "scans.read", "reports.read", "alerts.read",
    },
}


def can(role: UserRole, action: str) -> bool:
    perms = _PERMISSIONS.get(role, set())
    if action in perms:
        return True
    # Wildcard match: "assets.*" grants "assets.read", "assets.create", etc.
    prefix = action.split(".")[0] + ".*"
    return prefix in perms


def require_permission(action: str) -> Callable:
    """Decorator for FastAPI route handlers. Expects request.state.user to be set."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            from fastapi import HTTPException, Request
            request: Request = kwargs.get("request") or (args[0] if args else None)
            user = getattr(getattr(request, "state", None), "user", None)
            if user is None:
                raise HTTPException(status_code=401, detail="Not authenticated")
            if not can(user.role, action):
                raise HTTPException(
                    status_code=403,
                    detail=f"Role '{user.role.value}' does not have permission: {action}",
                )
            return await func(*args, **kwargs)
        return wrapper
    return decorator
