"""
audit.py - Backend audit logging module for Student Grade Portal.
Writes structured audit logs to logs/audit.log for security analysis and demonstration.
"""

import os
import json
import logging
from datetime import datetime, timezone

# Ensure logs/ directory exists
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
LOG_FILE = os.path.join(LOG_DIR, "audit.log")

os.makedirs(LOG_DIR, exist_ok=True)

# Configure a dedicated file logger
_audit_logger = logging.getLogger("audit")
_audit_logger.setLevel(logging.DEBUG)

if not _audit_logger.handlers:
    _handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _audit_logger.addHandler(_handler)


def write_audit_log(event_type, username=None, status="INFO", details=None, ip=None):
    """
    Write a single structured audit log entry.

    Args:
        event_type (str): Category of event, e.g. "LOGIN_SUCCESS", "ADMIN_ACCESS".
        username   (str): The user performing the action, or None if unknown.
        status     (str): Severity / outcome label – INFO | WARN | ERROR | DENIED.
        details   (dict): Extra key-value context to append.
        ip         (str): Client IP address, auto-resolved from Flask request if None.
    """
    # Try to pull the IP from the active Flask request context when not supplied.
    if ip is None:
        try:
            from flask import request as _req
            ip = _req.remote_addr or "unknown"
        except Exception:
            ip = "unknown"

    entry = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "event_type": event_type,
        "username": username or "anonymous",
        "status": status,
        "ip": ip,
        "details": details or {},
    }

    line = json.dumps(entry, ensure_ascii=False)
    _audit_logger.info(line)
    return entry


# ---------------------------------------------------------------------------
# Convenience wrappers
# ---------------------------------------------------------------------------

def log_login_success(username, ip=None):
    return write_audit_log(
        event_type="LOGIN_SUCCESS",
        username=username,
        status="INFO",
        details={"message": "User authenticated successfully"},
        ip=ip,
    )


def log_login_failure(username, reason="Invalid credentials", ip=None):
    return write_audit_log(
        event_type="LOGIN_FAILURE",
        username=username,
        status="WARN",
        details={"reason": reason},
        ip=ip,
    )


def log_logout(username, ip=None):
    return write_audit_log(
        event_type="LOGOUT",
        username=username,
        status="INFO",
        details={"message": "User logged out"},
        ip=ip,
    )


def log_profile_access(username, target_student_id=None, ip=None):
    return write_audit_log(
        event_type="PROFILE_ACCESS",
        username=username,
        status="INFO",
        details={"target_student_id": target_student_id or "self"},
        ip=ip,
    )


def log_results_access(username, target_student_id=None, ip=None):
    return write_audit_log(
        event_type="RESULTS_ACCESS",
        username=username,
        status="INFO",
        details={"target_student_id": target_student_id or "self"},
        ip=ip,
    )


def log_admin_access(username, allowed, ip=None):
    status = "INFO" if allowed else "DENIED"
    return write_audit_log(
        event_type="ADMIN_ACCESS",
        username=username,
        status=status,
        details={"allowed": allowed},
        ip=ip,
    )


def log_token_invalid(username, ip=None):
    return write_audit_log(
        event_type="TOKEN_INVALID",
        username=username,
        status="WARN",
        details={"message": "Missing or invalid JWT token"},
        ip=ip,
    )


def log_unauthorized(username, resource, ip=None):
    return write_audit_log(
        event_type="UNAUTHORIZED",
        username=username,
        status="DENIED",
        details={"resource": resource},
        ip=ip,
    )
