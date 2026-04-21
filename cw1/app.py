"""
app.py - Flask backend for Student Grade Portal.

Provides:
  - Page routes (serve HTML templates)
  - Auth API  : POST /login
  - User API  : GET  /me, GET /profile
  - Results   : GET  /results
  - Admin     : GET  /admin/users
  - Audit log : POST /audit/frontend  (accepts frontend log events)

This version uses SQLite for persistence while keeping the current frontend
route structure and JSON payload shapes intact.
"""

import datetime
import json
import sqlite3
from functools import wraps
from pathlib import Path

import jwt
from flask import Flask, g, jsonify, redirect, render_template, request, url_for
from flask_cors import CORS

from audit import (
    log_admin_access,
    log_login_failure,
    log_login_success,
    log_logout,
    log_profile_access,
    log_results_access,
    log_token_invalid,
    log_unauthorized,
    write_audit_log,
)

app = Flask(__name__)
CORS(app)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database" / "portal.db"

# Secret key used to sign JWTs (intentionally simple for demo purposes)
SECRET_KEY = "super-secret-demo-key-do-not-use-in-production"
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = 8


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

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


def json_dumps(value):
    return json.dumps(value or {}, ensure_ascii=False)


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


def fetch_user_by_username(username):
    return get_db().execute(
        """
        SELECT id, username, password, role, full_name, email, student_id
        FROM users
        WHERE username = ?
        """,
        (username,),
    ).fetchone()


def fetch_user_by_student_id(student_id):
    return get_db().execute(
        """
        SELECT id, username, password, role, full_name, email, student_id
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

    results = []
    for row in grade_rows:
        results.append(
            {
                "module": row["module_code"] or row["module_name"] or "",
                "module_code": row["module_code"],
                "module_name": row["module_name"],
                "academic_year": row["academic_year"],
                "mark": row["mark"],
                "grade": row["grade"],
            }
        )

    return {
        "student_id": user["student_id"],
        "username": user["username"],
        "full_name": user["full_name"],
        "results": results,
    }


def serialize_user_profile(user):
    return {
        "username": user["username"],
        "full_name": user["full_name"],
        "email": user["email"],
        "student_id": user["student_id"],
        "role": user["role"],
    }


# ---------------------------------------------------------------------------
# Audit helpers
# ---------------------------------------------------------------------------

def audit_login_success_event(user, ip_address):
    entry = log_login_success(user["username"], ip=ip_address)
    detail = {
        "message": "User authenticated successfully",
        "student_id": user["student_id"],
    }
    insert_audit_record(
        timestamp=entry["timestamp"],
        actor_username=user["username"],
        actor_role=user["role"],
        action="login",
        target=user["username"],
        success=True,
        ip_address=entry["ip"],
        detail=detail,
    )
    insert_login_attempt(
        timestamp=entry["timestamp"],
        username=user["username"],
        success=True,
        ip_address=entry["ip"],
        detail=detail,
    )


def audit_login_failure_event(username, ip_address, reason):
    attempted_username = username or "unknown"
    entry = log_login_failure(attempted_username, reason=reason, ip=ip_address)
    detail = {"reason": reason}
    insert_audit_record(
        timestamp=entry["timestamp"],
        actor_username=attempted_username,
        actor_role=None,
        action="login",
        target=attempted_username,
        success=False,
        ip_address=entry["ip"],
        detail=detail,
    )
    insert_login_attempt(
        timestamp=entry["timestamp"],
        username=attempted_username,
        success=False,
        ip_address=entry["ip"],
        detail=detail,
    )


def audit_logout_event(user_payload, ip_address):
    username = user_payload.get("username")
    entry = log_logout(username, ip=ip_address)
    insert_audit_record(
        timestamp=entry["timestamp"],
        actor_username=username,
        actor_role=user_payload.get("role"),
        action="logout",
        target=username,
        success=True,
        ip_address=entry["ip"],
        detail={"message": "User logged out"},
    )


def audit_profile_event(user_payload, target_student_id, success, ip_address):
    username = user_payload.get("username")
    entry = log_profile_access(username, target_student_id=target_student_id, ip=ip_address)
    insert_audit_record(
        timestamp=entry["timestamp"],
        actor_username=username,
        actor_role=user_payload.get("role"),
        action="profile_view",
        target=target_student_id or "self",
        success=success,
        ip_address=entry["ip"],
        detail={"target_student_id": target_student_id or "self"},
    )


def audit_results_event(user_payload, target_student_id, success, ip_address):
    username = user_payload.get("username")
    entry = log_results_access(username, target_student_id=target_student_id, ip=ip_address)
    insert_audit_record(
        timestamp=entry["timestamp"],
        actor_username=username,
        actor_role=user_payload.get("role"),
        action="results_view",
        target=target_student_id or "self",
        success=success,
        ip_address=entry["ip"],
        detail={"target_student_id": target_student_id or "self"},
    )


def audit_admin_access_event(user_payload, allowed, ip_address):
    username = user_payload.get("username")
    entry = log_admin_access(username, allowed=allowed, ip=ip_address)
    insert_audit_record(
        timestamp=entry["timestamp"],
        actor_username=username,
        actor_role=user_payload.get("role"),
        action="admin_access",
        target=request.path,
        success=allowed,
        ip_address=entry["ip"],
        detail={"allowed": allowed, "resource": request.path},
    )


def audit_token_invalid_event(ip_address):
    entry = log_token_invalid(username=None, ip=ip_address)
    insert_audit_record(
        timestamp=entry["timestamp"],
        actor_username="anonymous",
        actor_role=None,
        action="token_validation",
        target=request.path,
        success=False,
        ip_address=entry["ip"],
        detail={"message": "Missing or invalid JWT token"},
    )


def audit_unauthorized_event(user_payload, resource, ip_address):
    username = user_payload.get("username")
    entry = log_unauthorized(username, resource=resource, ip=ip_address)
    insert_audit_record(
        timestamp=entry["timestamp"],
        actor_username=username,
        actor_role=user_payload.get("role"),
        action="admin_access",
        target=resource,
        success=False,
        ip_address=entry["ip"],
        detail={"resource": resource},
    )


def infer_frontend_success(action):
    action_text = (action or "").upper()
    failure_markers = ("FAIL", "ERROR", "DENIED", "INVALID", "MISSING")
    return not any(marker in action_text for marker in failure_markers)


def maybe_decode_request_token():
    token = get_token_from_request()
    if not token:
        return None
    try:
        return decode_token(token)
    except jwt.PyJWTError:
        return None


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_token(user):
    payload = {
        "username": user["username"],
        "role": user["role"],
        "student_id": user["student_id"],
        "exp": datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(hours=TOKEN_EXPIRY_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_token(token):
    """Decode a JWT; returns payload dict or raises jwt.PyJWTError."""
    return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])


def get_token_from_request():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


def token_required(f):
    """Decorator: validates JWT and attaches the decoded payload to flask.g."""

    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_request()
        if not token:
            audit_token_invalid_event(request.remote_addr)
            return jsonify({"success": False, "message": "Token missing"}), 401
        try:
            g.current_user = decode_token(token)
        except jwt.ExpiredSignatureError:
            audit_token_invalid_event(request.remote_addr)
            return jsonify({"success": False, "message": "Token expired"}), 401
        except jwt.PyJWTError:
            audit_token_invalid_event(request.remote_addr)
            return jsonify({"success": False, "message": "Token invalid"}), 401
        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    """Decorator: requires token_required + admin role."""

    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if g.current_user.get("role") != "admin":
            audit_unauthorized_event(g.current_user, resource=request.path, ip_address=request.remote_addr)
            return jsonify({"success": False, "message": "Admin access required"}), 403
        return f(*args, **kwargs)

    return decorated


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Auth API
# ---------------------------------------------------------------------------

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    ip_address = request.remote_addr

    user = fetch_user_by_username(username)
    if not user or user["password"] != password:
        # Intentionally no rate limiting, lockout, or 429 response for demo use.
        audit_login_failure_event(username, ip_address, reason="Invalid credentials")
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

    token = create_token(user)
    audit_login_success_event(user, ip_address)

    return jsonify(
        {
            "success": True,
            "token": token,
            "user": {
                "username": user["username"],
                "role": user["role"],
                "student_id": user["student_id"],
                "full_name": user["full_name"],
                "email": user["email"],
            },
        }
    )


@app.route("/logout", methods=["POST"])
@token_required
def logout():
    audit_logout_event(g.current_user, request.remote_addr)
    return jsonify({"success": True, "message": "Logged out"})


# ---------------------------------------------------------------------------
# User / Profile API
# ---------------------------------------------------------------------------

@app.route("/me", methods=["GET"])
@token_required
def me():
    user = fetch_user_by_username(g.current_user.get("username"))
    audit_profile_event(g.current_user, target_student_id=None, success=bool(user), ip_address=request.remote_addr)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404
    return jsonify(serialize_user_profile(user))


@app.route("/profile", methods=["GET"])
@token_required
def profile():
    """
    Supports:
      GET /profile                   -> return current user's profile
      GET /profile?student_id=S001   -> return a specific student's profile

    NOTE: Ownership checks on student_id are intentionally omitted to keep the
    IDOR demo vulnerability in place.
    """

    student_id = request.args.get("student_id")
    if student_id:
        user = fetch_user_by_student_id(student_id)
    else:
        user = fetch_user_by_username(g.current_user.get("username"))

    audit_profile_event(
        g.current_user,
        target_student_id=student_id,
        success=bool(user),
        ip_address=request.remote_addr,
    )

    if not user:
        return jsonify({"success": False, "message": "Student not found"}), 404

    return jsonify(serialize_user_profile(user))


# ---------------------------------------------------------------------------
# Results API
# ---------------------------------------------------------------------------

@app.route("/results", methods=["GET"])
@token_required
def results():
    """
    Supports:
      GET /results                   -> return current user's results
      GET /results?student_id=S001   -> return a specific student's results

    NOTE: Ownership checks on student_id are intentionally omitted to keep the
    IDOR demo vulnerability in place.
    """

    student_id = request.args.get("student_id") or g.current_user.get("student_id")
    if not student_id:
        audit_results_event(
            g.current_user,
            target_student_id=None,
            success=False,
            ip_address=request.remote_addr,
        )
        return jsonify({"success": False, "message": "No student_id available"}), 400

    data = fetch_results_for_student(student_id)
    audit_results_event(
        g.current_user,
        target_student_id=student_id,
        success=bool(data),
        ip_address=request.remote_addr,
    )

    if not data:
        return jsonify({"success": False, "message": "No results found for this student"}), 404

    return jsonify(data)


# ---------------------------------------------------------------------------
# Admin API
# ---------------------------------------------------------------------------

@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_users():
    audit_admin_access_event(g.current_user, allowed=True, ip_address=request.remote_addr)

    users = [
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
    return jsonify(users)


# ---------------------------------------------------------------------------
# Frontend audit log ingestion (best effort – pages work even if this fails)
# ---------------------------------------------------------------------------

@app.route("/audit/frontend", methods=["POST"])
def audit_frontend():
    data = request.get_json(silent=True) or {}
    action = (data.get("action") or "UNKNOWN").upper()
    token_payload = maybe_decode_request_token() or {}
    actor_username = data.get("username") or token_payload.get("username")
    actor_role = data.get("role") or token_payload.get("role")
    detail = {
        "page": data.get("page"),
        "details": data.get("details", {}),
    }

    for key, value in data.items():
        if key not in ("action", "username", "role", "page", "details"):
            detail[key] = value

    entry = write_audit_log(
        event_type=f"FRONTEND_{action}",
        username=actor_username,
        status="INFO" if infer_frontend_success(action) else "WARN",
        details=detail,
        ip=request.remote_addr,
    )
    insert_audit_record(
        timestamp=entry["timestamp"],
        actor_username=actor_username or "anonymous",
        actor_role=actor_role,
        action=f"frontend_{action.lower()}",
        target=data.get("page") or request.path,
        success=infer_frontend_success(action),
        ip_address=entry["ip"],
        detail=detail,
    )
    return jsonify({"success": True}), 200


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
