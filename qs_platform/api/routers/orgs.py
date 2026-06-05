"""
Org management and user management routes.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from qs_platform.api.deps import get_current_user
from qs_platform.api.models import Org, User, UserRole
from qs_platform.api import store
from qs_platform.enterprise.auth import generate_api_key
from qs_platform.enterprise.audit import get_events, log_event
from qs_platform.enterprise.rbac import can

router = APIRouter(prefix="/org", tags=["org"])


@router.get("", response_model=Org)
async def get_org(user: User = Depends(get_current_user)):
    org = store.get_org(user.org_id)
    if not org:
        raise HTTPException(404, "Org not found")
    return org


@router.get("/users", response_model=list[User])
async def list_users(user: User = Depends(get_current_user)):
    if not can(user.role, "users.invite"):
        raise HTTPException(403, "Insufficient permissions")
    return store.list_users(user.org_id)


class InviteRequest(BaseModel):
    email: str
    name: str
    role: UserRole = UserRole.ANALYST


@router.post("/users/invite", response_model=User, status_code=201)
async def invite_user(
    body: InviteRequest,
    user: User = Depends(get_current_user),
):
    if not can(user.role, "users.invite"):
        raise HTTPException(403, "Insufficient permissions")

    existing = store.get_user_by_email(body.email)
    if existing and existing.org_id == user.org_id:
        raise HTTPException(409, "User with this email already exists in org")

    new_user = User(org_id=user.org_id, email=body.email, name=body.name, role=body.role)
    store.create_user(new_user)
    log_event(new_user.org_id, user.id, "user.invite", "user", new_user.id,
              {"email": body.email, "role": body.role.value})
    return new_user


@router.post("/api-keys", response_model=dict)
async def create_api_key(user: User = Depends(get_current_user)):
    key = generate_api_key(user.id)
    log_event(user.org_id, user.id, "apikey.create", "apikey", "new")
    return {"api_key": key, "note": "Store this securely — it will not be shown again."}


@router.get("/audit", response_model=list[dict])
async def get_audit_log(
    limit: int = 100,
    user: User = Depends(get_current_user),
):
    if not can(user.role, "audit.read"):
        raise HTTPException(403, "Insufficient permissions")
    events = get_events(user.org_id, limit=limit)
    return [e.model_dump() for e in events]
