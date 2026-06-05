"""
Authentication stubs — SSO (SAML 2.0 / OIDC), API key, and session management.

In production: replace _mock_* functions with real provider integrations.
SAML: python3-saml or pysaml2
OIDC: authlib or python-jose
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from qs_platform.api.models import User, UserRole, Org


# ── API Key auth (used for CI/CD and programmatic access) ─────────────────────

_API_KEY_STORE: dict[str, str] = {}  # hashed_key → user_id


def generate_api_key(user_id: str) -> str:
    """Generate a new API key for a user. Returns the plaintext key (shown once)."""
    raw = f"qs_{secrets.token_urlsafe(32)}"
    hashed = _hash_key(raw)
    _API_KEY_STORE[hashed] = user_id
    return raw


def validate_api_key(raw_key: str) -> Optional[str]:
    """Returns user_id if valid, None otherwise."""
    return _API_KEY_STORE.get(_hash_key(raw_key))


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


# ── Session tokens ────────────────────────────────────────────────────────────

@dataclass
class SessionToken:
    user_id: str
    org_id: str
    role: UserRole
    expires_at: datetime

    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at


_SESSION_STORE: dict[str, SessionToken] = {}


def create_session(user: User, ttl_hours: int = 8) -> str:
    token = secrets.token_urlsafe(48)
    _SESSION_STORE[token] = SessionToken(
        user_id=user.id,
        org_id=user.org_id,
        role=user.role,
        expires_at=datetime.utcnow() + timedelta(hours=ttl_hours),
    )
    return token


def validate_session(token: str) -> Optional[SessionToken]:
    session = _SESSION_STORE.get(token)
    if session and not session.is_expired:
        return session
    if session:
        del _SESSION_STORE[token]  # evict expired
    return None


def revoke_session(token: str) -> None:
    _SESSION_STORE.pop(token, None)


# ── SAML 2.0 stub ─────────────────────────────────────────────────────────────

class SAMLConfig:
    """Stub SAML SP configuration. Replace with real cert/metadata in production."""
    def __init__(self, sp_entity_id: str, idp_metadata_url: str, acs_url: str):
        self.sp_entity_id = sp_entity_id
        self.idp_metadata_url = idp_metadata_url
        self.acs_url = acs_url


def saml_initiate_login(config: SAMLConfig) -> str:
    """Returns the IdP redirect URL. Stub: returns a placeholder."""
    # TODO: use python3-saml to generate AuthnRequest
    return f"{config.idp_metadata_url}?SAMLRequest=STUB&RelayState=platform"


def saml_process_response(saml_response: str, config: SAMLConfig) -> dict:
    """
    Process IdP SAMLResponse. Returns dict with {email, name, groups}.
    Stub: always succeeds with a demo user.
    """
    # TODO: validate XML signature, parse assertions
    return {
        "email": "sso_user@example.com",
        "name": "SSO User",
        "groups": ["security-team"],
    }


# ── OIDC stub ─────────────────────────────────────────────────────────────────

class OIDCConfig:
    def __init__(self, issuer: str, client_id: str, client_secret: str, redirect_uri: str):
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri


def oidc_initiate_login(config: OIDCConfig) -> str:
    state = secrets.token_urlsafe(16)
    # TODO: use authlib to build proper authorization URL
    return f"{config.issuer}/authorize?client_id={config.client_id}&state={state}&redirect_uri={config.redirect_uri}&scope=openid+email+profile"


def oidc_exchange_code(code: str, config: OIDCConfig) -> dict:
    """Stub: exchange auth code for user claims."""
    # TODO: POST to token endpoint, validate id_token JWT
    return {
        "sub": "oidc|stub_user_001",
        "email": "oidc_user@example.com",
        "name": "OIDC User",
    }
