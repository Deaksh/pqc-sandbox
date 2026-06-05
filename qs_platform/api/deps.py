"""
FastAPI dependencies — shared across all routers.

get_current_user: returns the authenticated user, or the demo user in dev mode.
In production, enable the auth middleware in main.py and this will read
from request.state.user set by that middleware.
"""
from __future__ import annotations

from fastapi import Request
from qs_platform.api.models import User
from qs_platform.api import store


def get_current_user(request: Request) -> User:
    # If auth middleware is active it sets request.state.user
    user = getattr(request.state, "user", None)
    if user is not None:
        return user

    # Dev / no-auth fallback: return the seeded demo admin user
    demo = store.get_user("user_admin")
    if demo is None:
        # Should never happen — store.py seeds this user at import time
        raise RuntimeError("Demo user not found in store. Check store.py seed data.")
    return demo
