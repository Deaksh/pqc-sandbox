"""
QuantumShift Platform API — FastAPI application.

Run: uvicorn platform.api.main:app --reload --port 8080
Docs: http://localhost:8080/docs
"""
from __future__ import annotations

import datetime

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from qs_platform.api.routers import assets, reports, orgs, auth, vendors

app = FastAPI(
    title="QuantumShift Platform API",
    description=(
        "B2B compliance platform for post-quantum cryptography migration. "
        "Powered by pqc-sandbox (Apache 2.0 open core)."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — all localhost ports allowed in dev; lock down to your domain in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:3002",
        "https://app.quantumshift.io",
        "https://pqc-sandbox.vercel.app",
    ],
    allow_origin_regex=r"(http://localhost:\d+|https://.*\.vercel\.app)",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth middleware — skip for now to keep API explorable without tokens in dev
# In production: uncomment
# from qs_platform.api.middleware.auth_middleware import AuthMiddleware
# app.add_middleware(AuthMiddleware)

# ── Routes ────────────────────────────────────────────────────────────────────

app.include_router(auth.router, prefix="/api/v1")
app.include_router(assets.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")
app.include_router(orgs.router, prefix="/api/v1")
app.include_router(vendors.router, prefix="/api/v1")


@app.get("/", tags=["health"])
async def root():
    return {
        "service": "QuantumShift Platform API",
        "version": "0.1.0",
        "telemetry": False,
        "open_core": "pqc-sandbox (Apache 2.0)",
        "docs": "/docs",
    }


@app.get("/health", tags=["health"])
async def health():
    return {"status": "ok", "timestamp": datetime.datetime.utcnow().isoformat()}


@app.exception_handler(404)
async def not_found(request: Request, exc):
    return JSONResponse(status_code=404, content={"error": "Not found", "path": str(request.url.path)})


@app.exception_handler(500)
async def server_error(request: Request, exc):
    return JSONResponse(status_code=500, content={"error": "Internal server error"})
