"""
Reusable authentication helpers for the CW2 backend.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
import pyotp

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRY_HOURS = int(os.environ.get("CW2_ACCESS_TOKEN_HOURS", "8"))
TEMP_TOKEN_EXPIRY_MINUTES = int(os.environ.get("CW2_TEMP_TOKEN_MINUTES", "5"))
ACCESS_TOKEN_SECRET = os.environ.get(
    "CW2_JWT_SECRET",
    "cw2-demo-jwt-secret-change-me-32-bytes-min",
)
TEMP_TOKEN_SECRET = os.environ.get(
    "CW2_TEMP_TOKEN_SECRET",
    "cw2-demo-temp-secret-change-me-32-bytes-min",
)
TOTP_ISSUER = os.environ.get("CW2_TOTP_ISSUER", "Student Grade Portal CW2")

# Deterministic secrets keep the coursework demo reproducible across machines.
DEMO_TOTP_SECRETS = {
    "alice": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    "bob": "KRUGS4ZANFZSAYJAKRUGS4ZANFZSAYJA",
    "admin": "MFRGGZDFMZTWQ2LKMFRGGZDFMZTWQ2LK",
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    password_bytes = password.encode("utf-8")
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    password_bytes = password.encode("utf-8")
    hash_bytes = password_hash.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hash_bytes)


def _base_payload(user: dict, token_type: str, expires_delta: timedelta) -> dict:
    return {
        "sub": user["username"],
        "username": user["username"],
        "role": user["role"],
        "student_id": user["student_id"],
        "type": token_type,
        "exp": utc_now() + expires_delta,
    }


def create_access_token(user: dict) -> str:
    payload = _base_payload(
        user,
        token_type="access",
        expires_delta=timedelta(hours=ACCESS_TOKEN_EXPIRY_HOURS),
    )
    return jwt.encode(payload, ACCESS_TOKEN_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    payload = jwt.decode(token, ACCESS_TOKEN_SECRET, algorithms=[JWT_ALGORITHM])
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("Token is not an access token")
    return payload


def create_temp_token(user: dict) -> str:
    payload = _base_payload(
        user,
        token_type="mfa_temp",
        expires_delta=timedelta(minutes=TEMP_TOKEN_EXPIRY_MINUTES),
    )
    return jwt.encode(payload, TEMP_TOKEN_SECRET, algorithm=JWT_ALGORITHM)


def decode_temp_token(token: str) -> dict:
    payload = jwt.decode(token, TEMP_TOKEN_SECRET, algorithms=[JWT_ALGORITHM])
    if payload.get("type") != "mfa_temp":
        raise jwt.InvalidTokenError("Token is not an MFA temp token")
    return payload


def get_totp(secret: str) -> pyotp.TOTP:
    return pyotp.TOTP(secret)


def verify_totp(secret: str, code: str) -> bool:
    normalized = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(normalized) != 6:
        return False
    return get_totp(secret).verify(normalized, valid_window=1)


def build_totp_uri(username: str, secret: str) -> str:
    return get_totp(secret).provisioning_uri(name=username, issuer_name=TOTP_ISSUER)
