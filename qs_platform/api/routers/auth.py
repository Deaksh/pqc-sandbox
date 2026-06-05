"""
Authentication routes — login, SSO callbacks, logout.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from qs_platform.api import store
from qs_platform.enterprise.auth import create_session, revoke_session

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str
    password: str = ""   # stub: password auth not implemented; use SSO in production


class LoginResponse(BaseModel):
    token: str
    user_id: str
    org_id: str
    role: str


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest):
    """Stub login — looks up by email, creates session. Replace with real password auth."""
    user = store.get_user_by_email(body.email)
    if not user:
        # Auto-create for demo; remove in production
        raise HTTPException(401, "Invalid credentials")
    token = create_session(user)
    return LoginResponse(token=token, user_id=user.id, org_id=user.org_id, role=user.role.value)


@router.post("/logout", status_code=204)
async def logout(token: str):
    revoke_session(token)


class SSOCallbackRequest(BaseModel):
    saml_response: str = ""
    code: str = ""           # OIDC auth code
    state: str = ""


@router.post("/sso/callback", response_model=LoginResponse)
async def sso_callback(body: SSOCallbackRequest):
    """Stub SSO callback — returns a demo session. Wire up real SAML/OIDC in production."""
    # In production: validate SAML assertion or exchange OIDC code, look up/create user
    demo_user = store.get_user("user_admin")
    if not demo_user:
        raise HTTPException(500, "Demo user not found")
    token = create_session(demo_user)
    return LoginResponse(token=token, user_id=demo_user.id,
                         org_id=demo_user.org_id, role=demo_user.role.value)
