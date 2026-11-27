"""Thin FastAPI routes. No security logic lives in this file."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Header, Query
from pydantic import BaseModel, Field

try:  # package import (tests)
    from . import engine
except ImportError:  # `uvicorn main:app` from inside server/
    import engine  # type: ignore[no-redef]

router = APIRouter()


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    device_id: str = Field(default="", max_length=128)
    recovery_proof: str = Field(default="", max_length=20000)


class SendRequest(BaseModel):
    token: str = Field(min_length=1, description="Opaque reference from /api/login")
    sender: str = Field(min_length=1, max_length=128)
    recipient: str = Field(min_length=1, max_length=128)
    plaintext: str = Field(max_length=20000)


class AdminRotateRequest(BaseModel):
    token: str = Field(min_length=1)
    target_user: str = Field(min_length=1, max_length=128)


class RevokeRequest(BaseModel):
    token: str = Field(min_length=1)
    target_user: str = Field(min_length=1, max_length=128)
    target_device: str = Field(min_length=1, max_length=128)


class RecoveryRequest(BaseModel):
    token: str = Field(min_length=1)
    target_user: str = Field(min_length=1, max_length=128)
    new_device: str = Field(min_length=1, max_length=128)
    recovery_proof: str = Field(default="", max_length=20000)


class CrashRequest(BaseModel):
    token: str = Field(min_length=1)
    target_device: str = Field(default="", max_length=128)


class IntegrityTestRequest(BaseModel):
    token: str = Field(min_length=1)
    seq: Optional[int] = Field(default=None, ge=1)


class DemoProofRequest(BaseModel):
    purpose: str = Field(min_length=1, max_length=16)
    recovery_username: str = Field(default="", max_length=128)
    target_user: str = Field(default="", max_length=128)
    new_device: str = Field(default="", max_length=128)


def _bearer(authorization: Optional[str]) -> str:
    """Read the opaque reference from an Authorization header, never a URL."""
    if not authorization:
        raise engine.EngineError("unauthorized")
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        raise engine.EngineError("unauthorized")
    return value.strip()


@router.post("/api/demo/setup")
def demo_setup():
    return engine.demo_setup()


@router.post("/api/demo/reset")
def demo_reset():
    """Demo-only: force a fresh practice state after a previous run."""
    return engine.demo_setup(force=True)


@router.post("/api/demo/recovery-proof")
def demo_recovery_proof(body: DemoProofRequest):
    return engine.demo_recovery_proof(body.purpose, body.recovery_username,
                                      body.target_user, body.new_device)


@router.post("/api/login")
def login(body: LoginRequest):
    if body.recovery_proof:
        return engine.recovery_login(body.username, body.recovery_proof)
    if not body.device_id:
        raise engine.EngineError("invalid_request")
    return engine.login(body.username, body.device_id)


@router.get("/api/status")
def status():
    return engine.status()


@router.post("/api/messages/send")
def send_message(body: SendRequest):
    return engine.send_message(body.token, body.sender, body.recipient,
                               body.plaintext)


@router.get("/api/messages/{message_id}")
def read_message(message_id: str, recipient: str = Query(min_length=1),
                 authorization: Optional[str] = Header(default=None)):
    return engine.read_message(_bearer(authorization), recipient, message_id)


@router.post("/api/admin/rotate-key")
def rotate_key(body: AdminRotateRequest):
    return engine.rotate_key(body.token, body.target_user)


@router.post("/api/admin/revoke-device")
def revoke_device(body: RevokeRequest):
    return engine.revoke_device(body.token, body.target_user,
                                body.target_device)


@router.post("/api/recovery/enroll-device")
def enroll_device(body: RecoveryRequest):
    return engine.recover_device(body.token, body.target_user,
                                 body.new_device, body.recovery_proof)


@router.post("/api/admin/crash-recovery-test")
def crash_recovery_test(body: CrashRequest):
    return engine.crash_recovery_test(body.token, body.target_device)


@router.post("/api/admin/backup-integrity-test")
def backup_integrity_test(body: IntegrityTestRequest):
    return engine.backup_integrity_test(body.token)


@router.post("/api/admin/log-integrity-test")
def log_integrity_test(body: IntegrityTestRequest):
    return engine.log_integrity_test(body.token, body.seq)


@router.get("/api/detector/alerts")
def detector_alerts():
    return engine.alerts()


@router.post("/api/detector/run")
def detector_run():
    return engine.run_detector()


@router.get("/api/audit/verify")
def audit_verify():
    return engine.verify_audit()
