"""
Secure CW2 Flask backend for the Student Grade Portal.
"""

from __future__ import annotations

import json
import logging
import math
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import jwt
from flask import Flask, g, jsonify, redirect, render_template, request, url_for
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.errors import RateLimitExceeded
from flask_limiter.util import get_remote_address

from auth import create_access_token, create_temp_token, decode_access_token, decode_temp_token, verify_password, verify_totp

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database" / "portal.db"
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "audit.log"
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

MAX_FAILED_LOGINS = 5
LOCKOUT_WINDOW = timedelta(minutes=10)
LOGIN_RATE_LIMIT = "12 per minute"

LOG_DIR.mkdir(parents=True, exist_ok=True)

_audit_logger = logging.getLogger("cw2.audit")
_audit_logger.setLevel(logging.INFO)
_audit_logger.propagate = False
if not _audit_logger.handlers:
    _handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _audit_logger.addHandler(_handler)

app = Flask(
    __name__,
    template_folder=str(TEMPLATE_DIR),
    static_folder=str(STATIC_DIR),
    static_url_path="/static",
)
CORS(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri="memory://",
    default_limits=[],
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_timestamp(value: datetime | None = None) -> str:
    current = value or utc_now()
    return current.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def json_dumps(value: dict | None) -> str:
    return json.dumps(value or {}, ensure_ascii=False)


def json_loads(value: str | None) -> dict:
    if not value:
        return {}
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return {}


def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        g._db = db
    return db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("_db", None)
    if db is not None:
        db.close()


def get_request_ip() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def write_audit_log(event_type, username=None, status="INFO", details=None, ip=None):
    entry = {
        "timestamp": iso_timestamp(),
        "event_type": event_type,
        "username": username or "anonymous",
        "status": status,
        "ip": ip or get_request_ip(),
        "details": details or {},
    }
    _audit_logger.info(json.dumps(entry, ensure_ascii=False))
    return entry


def insert_audit_record(timestamp, actor_username, actor_role, action, target, success, ip_address, detail):
    get_db().execute(
        """
        INSERT INTO audit_log (
            timestamp, actor_username, actor_role, action,
            target, success, ip_address, detail
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            actor_username,
            actor_role,
            action,
            target,
            1 if success else 0,
            ip_address,
            json_dumps(detail),
        ),
    )
    get_db().commit()


def insert_login_attempt(timestamp, username, success, ip_address, detail):
    get_db().execute(
        """
        INSERT INTO login_attempts (timestamp, username, success, ip_address, detail)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            username,
            1 if success else 0,
            ip_address,
            json_dumps(detail),
        ),
    )
    get_db().commit()


def record_audit_event(
    *,
    event_type: str,
    action: str,
    target: str,
    success: bool,
    actor_username: str | None,
    actor_role: str | None,
    detail: dict | None,
    ip_address: str | None = None,
    status: str | None = None,
):
    final_status = status or ("INFO" if success else "WARN")
    entry = write_audit_log(
        event_type=event_type,
        username=actor_username,
        status=final_status,
        details=detail,
        ip=ip_address,
    )
    insert_audit_record(
        timestamp=entry["timestamp"],
        actor_username=actor_username or "anonymous",
        actor_role=actor_role,
        action=action,
        target=target,
        success=success,
        ip_address=entry["ip"],
        detail=detail,
    )
    return entry


def record_login_attempt(username: str | None, success: bool, ip_address: str, detail: dict):
    insert_login_attempt(
        timestamp=iso_timestamp(),
        username=username or "unknown",
        success=success,
        ip_address=ip_address,
        detail=detail,
    )


def fetch_user_by_username(username):
    return get_db().execute(
        """
        SELECT id, username, password_hash, role, full_name, email, student_id, totp_secret
        FROM users
        WHERE username = ?
        """,
        (username,),
    ).fetchone()


def fetch_user_by_student_id(student_id):
    return get_db().execute(
        """
        SELECT id, username, password_hash, role, full_name, email, student_id, totp_secret
        FROM users
        WHERE student_id = ?
        """,
        (student_id,),
    ).fetchone()


def fetch_all_users():
    return get_db().execute(
        """
        SELECT id, username, full_name, email, student_id, role
        FROM users
        ORDER BY id
        """
    ).fetchall()


def fetch_results_for_student(student_id):
    user = get_db().execute(
        """
        SELECT username, full_name, student_id
        FROM users
        WHERE student_id = ?
        """,
        (student_id,),
    ).fetchone()
    if not user:
        return None

    grade_rows = get_db().execute(
        """
        SELECT module_code, module_name, academic_year, mark, grade
        FROM grades
        WHERE student_id = ?
        ORDER BY id
        """,
        (student_id,),
    ).fetchall()

    return {
        "student_id": user["student_id"],
        "username": user["username"],
        "full_name": user["full_name"],
        "results": [
            {
                "module": row["module_code"] or row["module_name"] or "",
                "module_code": row["module_code"],
                "module_name": row["module_name"],
                "academic_year": row["academic_year"],
                "mark": row["mark"],
                "grade": row["grade"],
            }
            for row in grade_rows
        ],
    }


def serialize_user_profile(user):
    return {
        "username": user["username"],
        "full_name": user["full_name"],
        "email": user["email"],
        "student_id": user["student_id"],
        "role": user["role"],
    }


def get_bearer_token() -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


def safe_decode_access_token():
    token = get_bearer_token()
    if not token:
        return None
    try:
        return decode_access_token(token)
    except jwt.PyJWTError:
        return None


def infer_frontend_success(action: str) -> bool:
    action_text = (action or "").upper()
    failure_markers = ("FAIL", "ERROR", "DENIED", "INVALID", "MISSING")
    return not any(marker in action_text for marker in failure_markers)


def load_recent_login_rows(username: str, since_timestamp: str):
    return get_db().execute(
        """
        SELECT timestamp, success, detail
        FROM login_attempts
        WHERE username = ? AND timestamp >= ?
        ORDER BY id ASC
        """,
        (username, since_timestamp),
    ).fetchall()


def is_password_failure(row) -> bool:
    detail = json_loads(row["detail"])
    return (
        not bool(row["success"])
        and detail.get("phase") == "password"
        and detail.get("reason") == "invalid_credentials"
    )


def is_password_success(row) -> bool:
    detail = json_loads(row["detail"])
    return bool(row["success"]) and detail.get("phase") == "password"


def get_lockout_state(username: str) -> dict:
    if not username:
        return {"locked": False, "failure_count": 0, "locked_until": None, "remaining_seconds": 0}

    window_start = utc_now() - LOCKOUT_WINDOW
    rows = load_recent_login_rows(username, iso_timestamp(window_start))

    reset_index = 0
    for index, row in enumerate(rows):
        if is_password_success(row):
            reset_index = index + 1

    relevant_rows = rows[reset_index:]
    failures = [row for row in relevant_rows if is_password_failure(row)]

    if len(failures) < MAX_FAILED_LOGINS:
        return {
            "locked": False,
            "failure_count": len(failures),
            "locked_until": None,
            "remaining_seconds": 0,
        }

    last_failure_at = parse_timestamp(failures[-1]["timestamp"])
    locked_until = last_failure_at + LOCKOUT_WINDOW
    remaining_seconds = max(0, math.ceil((locked_until - utc_now()).total_seconds()))

    return {
        "locked": remaining_seconds > 0,
        "failure_count": len(failures),
        "locked_until": iso_timestamp(locked_until),
        "remaining_seconds": remaining_seconds,
    }


def login_rate_limit_key():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    return username or get_remote_address()


def extract_login_username():
    data = request.get_json(silent=True) or {}
    return (data.get("username") or "").strip() or None


def record_token_invalid(message: str):
    record_audit_event(
        event_type="TOKEN_INVALID",
        action="token_validation",
        target=request.path,
        success=False,
        actor_username=None,
        actor_role=None,
        detail={"message": message},
        ip_address=get_request_ip(),
        status="WARN",
    )


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_bearer_token()
        if not token:
            record_token_invalid("Token missing")
            return jsonify({"success": False, "message": "Token missing"}), 401
        try:
            g.current_user = decode_access_token(token)
        except jwt.ExpiredSignatureError:
            record_token_invalid("Token expired")
            return jsonify({"success": False, "message": "Token expired"}), 401
        except jwt.PyJWTError:
            record_token_invalid("Token invalid")
            return jsonify({"success": False, "message": "Token invalid"}), 401
        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if g.current_user.get("role") != "admin":
            record_audit_event(
                event_type="UNAUTHORIZED",
                action="admin_access",
                target=request.path,
                success=False,
                actor_username=g.current_user.get("username"),
                actor_role=g.current_user.get("role"),
                detail={"resource": request.path, "reason": "Admin access required"},
                ip_address=get_request_ip(),
                status="DENIED",
            )
            return jsonify({"success": False, "message": "Admin access required"}), 403
        return f(*args, **kwargs)

    return decorated


def enforce_student_ownership(requested_student_id: str, resource: str) -> bool:
    current_user = g.current_user
    current_role = current_user.get("role")
    token_student_id = current_user.get("student_id")

    if current_role == "admin":
        return True
    if requested_student_id == token_student_id:
        return True

    record_audit_event(
        event_type="IDOR_BLOCKED",
        action="idor_block",
        target=requested_student_id,
        success=False,
        actor_username=current_user.get("username"),
        actor_role=current_role,
        detail={
            "resource": resource,
            "requested_student_id": requested_student_id,
            "token_student_id": token_student_id,
            "reason": "Ownership check failed",
        },
        ip_address=get_request_ip(),
        status="DENIED",
    )
    return False


def record_resource_access(resource: str, target: str, success: bool, access_mode: str, detail: dict | None = None):
    payload = {
        "resource": resource,
        "target_student_id": target,
        "access_mode": access_mode,
    }
    if detail:
        payload.update(detail)

    record_audit_event(
        event_type=f"{resource.upper()}_ACCESS",
        action=f"{resource}_view",
        target=target,
        success=success,
        actor_username=g.current_user.get("username"),
        actor_role=g.current_user.get("role"),
        detail=payload,
        ip_address=get_request_ip(),
        status="INFO" if success else "WARN",
    )


@app.errorhandler(429)
def handle_rate_limit(error):
    if request.path == "/login":
        username = extract_login_username()
        ip_address = get_request_ip()
        detail = {
            "phase": "rate_limit",
            "reason": "Too many requests to /login",
            "limit": str(error.description),
            "http_status": 429,
        }
        record_login_attempt(username, False, ip_address, detail)
        record_audit_event(
            event_type="LOGIN_RATE_LIMITED",
            action="login_rate_limit",
            target=username or "/login",
            success=False,
            actor_username=username,
            actor_role=None,
            detail=detail,
            ip_address=ip_address,
            status="DENIED",
        )
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Too many requests. Please wait before trying again.",
                }
            ),
            429,
        )
    if isinstance(error, RateLimitExceeded):
        return jsonify({"success": False, "message": "Too many requests"}), 429
    return error


@app.route("/")
def index():
    return redirect(url_for("login_page"))


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/dashboard")
def dashboard_page():
    return render_template("dashboard.html")


@app.route("/profile-page")
def profile_page():
    return render_template("profile.html")


@app.route("/results-page")
def results_page():
    return render_template("results.html")


@app.route("/admin-page")
def admin_page():
    return render_template("admin.html")


@app.route("/login", methods=["POST"])
@limiter.limit(LOGIN_RATE_LIMIT, key_func=login_rate_limit_key)
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    ip_address = get_request_ip()

    if not username or not password:
        detail = {"phase": "password", "reason": "missing_fields", "http_status": 400}
        record_login_attempt(username, False, ip_address, detail)
        record_audit_event(
            event_type="LOGIN_FAILURE",
            action="login",
            target=username or "/login",
            success=False,
            actor_username=username,
            actor_role=None,
            detail=detail,
            ip_address=ip_address,
            status="WARN",
        )
        return jsonify({"success": False, "message": "Username and password are required"}), 400

    lockout_state = get_lockout_state(username)
    if lockout_state["locked"]:
        detail = {
            "phase": "lockout",
            "reason": "Account locked after repeated failures",
            "failures_in_window": lockout_state["failure_count"],
            "locked_until": lockout_state["locked_until"],
            "retry_after_seconds": lockout_state["remaining_seconds"],
            "http_status": 429,
        }
        record_login_attempt(username, False, ip_address, detail)
        record_audit_event(
            event_type="LOGIN_LOCKED",
            action="login_lockout",
            target=username,
            success=False,
            actor_username=username,
            actor_role=None,
            detail=detail,
            ip_address=ip_address,
            status="DENIED",
        )
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Account temporarily locked due to repeated failed logins",
                    "retry_after_seconds": lockout_state["remaining_seconds"],
                }
            ),
            429,
        )

    user = fetch_user_by_username(username)
    if not user or not verify_password(password, user["password_hash"]):
        detail = {"phase": "password", "reason": "invalid_credentials", "http_status": 401}
        record_login_attempt(username, False, ip_address, detail)
        record_audit_event(
            event_type="LOGIN_FAILURE",
            action="login",
            target=username,
            success=False,
            actor_username=username,
            actor_role=None,
            detail=detail,
            ip_address=ip_address,
            status="WARN",
        )
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

    temp_token = create_temp_token(user)
    detail = {
        "phase": "password",
        "message": "Password verified; MFA required",
        "mfa_required": True,
    }
    record_login_attempt(user["username"], True, ip_address, detail)
    record_audit_event(
        event_type="MFA_CHALLENGE_ISSUED",
        action="login_password",
        target=user["username"],
        success=True,
        actor_username=user["username"],
        actor_role=user["role"],
        detail=detail,
        ip_address=ip_address,
        status="INFO",
    )
    return jsonify(
        {
            "success": True,
            "mfa_required": True,
            "temp_token": temp_token,
            "message": "Password verified. Enter your MFA code to continue.",
            "user": serialize_user_profile(user),
        }
    )


@app.route("/login/mfa", methods=["POST"])
def login_mfa():
    data = request.get_json(silent=True) or {}
    temp_token = data.get("temp_token") or ""
    otp = data.get("otp") or data.get("code") or data.get("totp_code") or ""
    ip_address = get_request_ip()

    if not temp_token or not otp:
        record_audit_event(
            event_type="MFA_FAILURE",
            action="login_mfa",
            target="/login/mfa",
            success=False,
            actor_username=None,
            actor_role=None,
            detail={"reason": "temp_token and otp are required"},
            ip_address=ip_address,
            status="WARN",
        )
        return jsonify({"success": False, "message": "temp_token and otp are required"}), 400

    try:
        temp_payload = decode_temp_token(temp_token)
    except jwt.ExpiredSignatureError:
        record_audit_event(
            event_type="MFA_FAILURE",
            action="login_mfa",
            target="/login/mfa",
            success=False,
            actor_username=None,
            actor_role=None,
            detail={"reason": "MFA session expired"},
            ip_address=ip_address,
            status="WARN",
        )
        return jsonify({"success": False, "message": "MFA session expired"}), 401
    except jwt.PyJWTError:
        record_audit_event(
            event_type="MFA_FAILURE",
            action="login_mfa",
            target="/login/mfa",
            success=False,
            actor_username=None,
            actor_role=None,
            detail={"reason": "Invalid MFA session"},
            ip_address=ip_address,
            status="WARN",
        )
        return jsonify({"success": False, "message": "Invalid MFA session"}), 401

    user = fetch_user_by_username(temp_payload.get("username"))
    if not user:
        record_audit_event(
            event_type="MFA_FAILURE",
            action="login_mfa",
            target=temp_payload.get("username") or "/login/mfa",
            success=False,
            actor_username=temp_payload.get("username"),
            actor_role=temp_payload.get("role"),
            detail={"reason": "User not found for MFA session"},
            ip_address=ip_address,
            status="WARN",
        )
        return jsonify({"success": False, "message": "Invalid MFA session"}), 401

    if not verify_totp(user["totp_secret"], otp):
        record_audit_event(
            event_type="MFA_FAILURE",
            action="login_mfa",
            target=user["username"],
            success=False,
            actor_username=user["username"],
            actor_role=user["role"],
            detail={"reason": "Invalid MFA code"},
            ip_address=ip_address,
            status="WARN",
        )
        return jsonify({"success": False, "message": "Invalid MFA code"}), 401

    token = create_access_token(user)
    record_audit_event(
        event_type="LOGIN_SUCCESS",
        action="login",
        target=user["username"],
        success=True,
        actor_username=user["username"],
        actor_role=user["role"],
        detail={"phase": "mfa", "message": "User authenticated successfully"},
        ip_address=ip_address,
        status="INFO",
    )
    return jsonify(
        {
            "success": True,
            "message": "Login successful",
            "token": token,
            "user": serialize_user_profile(user),
        }
    )


@app.route("/logout", methods=["POST"])
@token_required
def logout():
    record_audit_event(
        event_type="LOGOUT",
        action="logout",
        target=g.current_user.get("username"),
        success=True,
        actor_username=g.current_user.get("username"),
        actor_role=g.current_user.get("role"),
        detail={"message": "User logged out"},
        ip_address=get_request_ip(),
        status="INFO",
    )
    return jsonify({"success": True, "message": "Logged out"})


@app.route("/me", methods=["GET"])
@token_required
def me():
    user = fetch_user_by_username(g.current_user.get("username"))
    record_resource_access(
        resource="profile",
        target=g.current_user.get("student_id") or "self",
        success=bool(user),
        access_mode="self",
    )
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404
    return jsonify(serialize_user_profile(user))


@app.route("/profile", methods=["GET"])
@token_required
def profile():
    requested_student_id = (request.args.get("student_id") or "").strip() or None

    if requested_student_id:
        if not enforce_student_ownership(requested_student_id, "profile"):
            return jsonify({"success": False, "message": "Forbidden"}), 403
        user = fetch_user_by_student_id(requested_student_id)
        access_mode = (
            "admin_override"
            if g.current_user.get("role") == "admin"
            else "owned_record"
        )
        target = requested_student_id
    else:
        user = fetch_user_by_username(g.current_user.get("username"))
        access_mode = "self"
        target = g.current_user.get("student_id") or "self"

    record_resource_access(
        resource="profile",
        target=target,
        success=bool(user),
        access_mode=access_mode,
    )
    if not user:
        return jsonify({"success": False, "message": "Student not found"}), 404
    return jsonify(serialize_user_profile(user))


@app.route("/results", methods=["GET"])
@token_required
def results():
    requested_student_id = (request.args.get("student_id") or "").strip() or None

    if requested_student_id:
        if not enforce_student_ownership(requested_student_id, "results"):
            return jsonify({"success": False, "message": "Forbidden"}), 403
        student_id = requested_student_id
        access_mode = (
            "admin_override"
            if g.current_user.get("role") == "admin"
            else "owned_record"
        )
    else:
        student_id = g.current_user.get("student_id")
        access_mode = "self"

    if not student_id:
        record_resource_access(
            resource="results",
            target="self",
            success=False,
            access_mode=access_mode,
            detail={"reason": "No student_id available"},
        )
        return jsonify({"success": False, "message": "No student_id available"}), 400

    data = fetch_results_for_student(student_id)
    record_resource_access(
        resource="results",
        target=student_id,
        success=bool(data),
        access_mode=access_mode,
    )
    if not data:
        return jsonify({"success": False, "message": "No results found for this student"}), 404
    return jsonify(data)


@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_users():
    record_audit_event(
        event_type="ADMIN_ACCESS",
        action="admin_access",
        target=request.path,
        success=True,
        actor_username=g.current_user.get("username"),
        actor_role=g.current_user.get("role"),
        detail={"allowed": True, "resource": request.path},
        ip_address=get_request_ip(),
        status="INFO",
    )
    return jsonify(
        [
            {
                "id": row["id"],
                "username": row["username"],
                "full_name": row["full_name"],
                "email": row["email"],
                "student_id": row["student_id"],
                "role": row["role"],
            }
            for row in fetch_all_users()
        ]
    )


@app.route("/audit/frontend", methods=["POST"])
def audit_frontend():
    data = request.get_json(silent=True) or {}
    action = (data.get("action") or "UNKNOWN").upper()
    token_payload = safe_decode_access_token() or {}
    actor_username = data.get("username") or token_payload.get("username")
    actor_role = data.get("role") or token_payload.get("role")

    detail = {
        "page": data.get("page"),
        "details": data.get("details", {}),
    }
    for key, value in data.items():
        if key not in ("action", "username", "role", "page", "details"):
            detail[key] = value

    record_audit_event(
        event_type=f"FRONTEND_{action}",
        action=f"frontend_{action.lower()}",
        target=data.get("page") or request.path,
        success=infer_frontend_success(action),
        actor_username=actor_username,
        actor_role=actor_role,
        detail=detail,
        ip_address=get_request_ip(),
        status="INFO" if infer_frontend_success(action) else "WARN",
    )
    return jsonify({"success": True}), 200


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
