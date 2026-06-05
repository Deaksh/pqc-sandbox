"""
FastAPI middleware for authentication — validates session tokens and API keys.
Attaches user context to request.state.user.
"""
from __future__ import annotations

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from qs_platform.enterprise.auth import validate_session, validate_api_key
from qs_platform.api.store import get_user

# Routes that do not require authentication
_PUBLIC_PATHS = {"/", "/health", "/docs", "/openapi.json", "/redoc",
                 "/api/v1/auth/login", "/api/v1/auth/sso/callback"}


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in _PUBLIC_PATHS or request.url.path.startswith("/static"):
            return await call_next(request)

        user_id = None

        # 1. Check Bearer token (session)
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
            session = validate_session(token)
            if session:
                user_id = session.user_id

        # 2. Fall back to X-API-Key header
        if not user_id:
            api_key = request.headers.get("X-API-Key", "")
            if api_key:
                user_id = validate_api_key(api_key)

        if not user_id:
            return JSONResponse(status_code=401, content={"error": "Not authenticated"})

        user = get_user(user_id)
        if not user:
            return JSONResponse(status_code=401, content={"error": "User not found"})

        request.state.user = user
        return await call_next(request)
