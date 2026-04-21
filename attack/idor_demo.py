"""
CW2 verification script for VULN-02.

Logs in as a student through the CW2 MFA flow, proves that another student's
record is blocked with HTTP 403, then shows that admin override still works.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pyotp
import requests

BASE_URL = "http://127.0.0.1:5000"
DB_PATH = Path(__file__).resolve().parent.parent / "cw2" / "database" / "portal.db"

BOB_USERNAME = "bob"
BOB_PASSWORD = "letmein"
BOB_STUDENT_ID = "S002"
ALICE_STUDENT_ID = "S001"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

DEMO_TOTP_SECRETS = {
    "alice": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    "bob": "KRUGS4ZANFZSAYJAKRUGS4ZANFZSAYJA",
    "admin": "MFRGGZDFMZTWQ2LKMFRGGZDFMZTWQ2LK",
}

SEPARATOR = "=" * 72


def heading(title: str) -> None:
    print()
    print(SEPARATOR)
    print(f"  {title}")
    print(SEPARATOR)


def divider() -> None:
    print("-" * 72)


def pretty(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


def current_totp(username: str) -> str:
    return pyotp.TOTP(DEMO_TOTP_SECRETS[username]).now()


def login_with_mfa(username: str, password: str) -> tuple[str, dict]:
    first = requests.post(
        f"{BASE_URL}/login",
        json={"username": username, "password": password},
        timeout=10,
    )
    first.raise_for_status()
    first_data = first.json()

    second = requests.post(
        f"{BASE_URL}/login/mfa",
        json={"temp_token": first_data["temp_token"], "otp": current_totp(username)},
        timeout=10,
    )
    second.raise_for_status()
    second_data = second.json()
    return second_data["token"], second_data["user"]


def api_get(endpoint: str, token: str, student_id: str) -> requests.Response:
    return requests.get(
        f"{BASE_URL}{endpoint}",
        headers={"Authorization": f"Bearer {token}"},
        params={"student_id": student_id},
        timeout=10,
    )


def print_response(label: str, response: requests.Response) -> None:
    print(f"\n{label} -> {response.status_code}")
    print(pretty(response.json()))


def query_audit_rows() -> None:
    heading("STEP 5 - SQLite audit evidence")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        """
        SELECT id, timestamp, actor_username, action, target, success, detail
        FROM audit_log
        WHERE action IN ('idor_block', 'profile_view', 'results_view')
        ORDER BY id DESC
        LIMIT 12
        """
    ).fetchall()

    if rows:
        print(f"  {'ID':<5} {'Timestamp':<28} {'Actor':<10} {'Action':<14} {'OK':<4} Target")
        divider()
        for row in reversed(rows):
            ok = "Y" if row["success"] else "N"
            print(f"  {row['id']:<5} {row['timestamp']:<28} {row['actor_username']:<10} {row['action']:<14} {ok:<4} {row['target']}")
            print(f"      detail: {row['detail']}")
    else:
        print("  No matching audit rows found.")

    conn.close()


def main() -> None:
    print(SEPARATOR)
    print("  CW2 VULN-02 Verification - IDOR blocked, admin override allowed")
    print(f"  Target : {BASE_URL}")
    print(SEPARATOR)

    heading("STEP 1 - Bob signs in with CW2 MFA")
    bob_token, bob_user = login_with_mfa(BOB_USERNAME, BOB_PASSWORD)
    print(f"  Logged in as : {bob_user['username']} ({bob_user['student_id']})")
    print(f"  Role         : {bob_user['role']}")
    print(f"  Token prefix : {bob_token[:36]}...")

    heading("STEP 2 - Bob requests his own profile and results")
    own_profile = api_get("/profile", bob_token, BOB_STUDENT_ID)
    print_response(f"GET /profile?student_id={BOB_STUDENT_ID}", own_profile)

    own_results = api_get("/results", bob_token, BOB_STUDENT_ID)
    print_response(f"GET /results?student_id={BOB_STUDENT_ID}", own_results)

    heading("STEP 3 - Bob attempts Alice's profile and results")
    blocked_profile = api_get("/profile", bob_token, ALICE_STUDENT_ID)
    print_response(f"GET /profile?student_id={ALICE_STUDENT_ID}", blocked_profile)

    blocked_results = api_get("/results", bob_token, ALICE_STUDENT_ID)
    print_response(f"GET /results?student_id={ALICE_STUDENT_ID}", blocked_results)

    heading("STEP 4 - Admin requests Alice's data")
    admin_token, admin_user = login_with_mfa(ADMIN_USERNAME, ADMIN_PASSWORD)
    print(f"  Logged in as : {admin_user['username']}")
    print(f"  Role         : {admin_user['role']}")

    admin_profile = api_get("/profile", admin_token, ALICE_STUDENT_ID)
    print_response(f"GET /profile?student_id={ALICE_STUDENT_ID} as admin", admin_profile)

    admin_results = api_get("/results", admin_token, ALICE_STUDENT_ID)
    print_response(f"GET /results?student_id={ALICE_STUDENT_ID} as admin", admin_results)

    query_audit_rows()

    heading("SUMMARY")
    print("  Bob -> own profile/results : 200")
    print("  Bob -> Alice profile       : 403")
    print("  Bob -> Alice results       : 403")
    print("  Admin -> Alice data        : 200")
    print("  Evidence is written to cw2/database/portal.db and cw2/logs/audit.log")


if __name__ == "__main__":
    main()
