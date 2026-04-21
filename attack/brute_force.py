"""
CW2 verification script for VULN-01.

Shows that repeated wrong passwords trigger account lockout and HTTP 429,
then queries the CW2 SQLite database for evidence.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import requests

BASE_URL = "http://127.0.0.1:5000"
TARGET_USERNAME = "alice"
CORRECT_PASSWORD = "password123"
DB_PATH = Path(__file__).resolve().parent.parent / "cw2" / "database" / "portal.db"

WRONG_PASSWORDS = [
    "wrong1",
    "wrong2",
    "wrong3",
    "wrong4",
    "wrong5",
    "wrong6",
    "wrong7",
]
DELAY_BETWEEN_REQUESTS = 0.3
SEPARATOR = "=" * 72


def post_login(username: str, password: str) -> requests.Response:
    return requests.post(
        f"{BASE_URL}/login",
        json={"username": username, "password": password},
        timeout=5,
    )


def heading(title: str) -> None:
    print()
    print(SEPARATOR)
    print(f"  {title}")
    print(SEPARATOR)


def divider() -> None:
    print("-" * 72)


def status_label(code: int) -> str:
    labels = {200: "PASSWORD OK", 401: "WRONG CREDS", 429: "LOCKED OUT"}
    return labels.get(code, f"HTTP {code}")


def phase1_wrong_attempts() -> list[dict]:
    heading("PHASE 1 - Wrong password attempts")
    print(f"  {'#':<4} {'Password':<14} {'Status':<6} {'Label':<14} Response")
    divider()

    results = []
    for index, password in enumerate(WRONG_PASSWORDS, start=1):
        response = post_login(TARGET_USERNAME, password)
        body = response.json()
        message = body.get("message", body.get("error", ""))
        print(f"  {index:<4} {password:<14} {response.status_code:<6} {status_label(response.status_code):<14} {message}")
        results.append(
            {
                "attempt": index,
                "password": password,
                "status": response.status_code,
                "body": body,
            }
        )
        time.sleep(DELAY_BETWEEN_REQUESTS)
    return results


def phase2_correct_attempt() -> dict:
    heading("PHASE 2 - Correct password while lockout is active")
    response = post_login(TARGET_USERNAME, CORRECT_PASSWORD)
    body = response.json()
    message = body.get("message", body.get("error", ""))

    print(f"  {'#':<4} {'Password':<14} {'Status':<6} {'Label':<14} Response")
    divider()
    print(f"  {'8':<4} {CORRECT_PASSWORD:<14} {response.status_code:<6} {status_label(response.status_code):<14} {message}")

    return {
        "attempt": 8,
        "password": CORRECT_PASSWORD,
        "status": response.status_code,
        "body": body,
    }


def phase3_summary(wrong_results: list[dict], correct_result: dict) -> None:
    heading("SUMMARY - Before/After defence comparison")
    print(f"  {'Attempt':<10} {'Password':<14} {'HTTP':<6} CW1 (expected)         CW2 (observed)")
    divider()

    for item in wrong_results + [correct_result]:
        cw1_result = "401 -> keep trying"
        if item["status"] == 429:
            cw2_result = "429 -> blocked"
        elif item["status"] == 200:
            cw2_result = "200 -> password step ok"
        else:
            cw2_result = "401 -> keep trying"
        print(f"  {item['attempt']:<10} {item['password']:<14} {item['status']:<6} {cw1_result:<22} {cw2_result}")

    print()
    print(f"  Lockout starts on attempt 6: {'yes' if wrong_results[5]['status'] == 429 else 'no'}")
    print(f"  Correct password blocked during lockout: {'yes' if correct_result['status'] == 429 else 'no'}")


def phase4_db_evidence() -> None:
    heading("DB EVIDENCE - Recent login_attempts for alice")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        """
        SELECT id, timestamp, username, success, ip_address, detail
        FROM login_attempts
        WHERE username = ?
        ORDER BY id DESC
        LIMIT 10
        """,
        (TARGET_USERNAME,),
    ).fetchall()

    if rows:
        print(f"  {'ID':<5} {'Timestamp':<28} {'User':<8} {'OK':<4} Detail")
        divider()
        for row in reversed(rows):
            ok = "Y" if row["success"] else "N"
            print(f"  {row['id']:<5} {row['timestamp']:<28} {row['username']:<8} {ok:<4} {row['detail']}")
    else:
        print("  No login_attempts rows found.")

    heading("DB EVIDENCE - Recent audit_log login events")

    rows = conn.execute(
        """
        SELECT id, timestamp, actor_username, action, success, detail
        FROM audit_log
        WHERE actor_username = ?
          AND action IN ('login', 'login_lockout', 'login_rate_limit')
        ORDER BY id DESC
        LIMIT 10
        """,
        (TARGET_USERNAME,),
    ).fetchall()

    if rows:
        print(f"  {'ID':<5} {'Timestamp':<28} {'Action':<16} {'OK':<4} Detail")
        divider()
        for row in reversed(rows):
            ok = "Y" if row["success"] else "N"
            print(f"  {row['id']:<5} {row['timestamp']:<28} {row['action']:<16} {ok:<4} {row['detail']}")
    else:
        print("  No audit_log rows found.")

    conn.close()


def main() -> None:
    print(SEPARATOR)
    print("  CW2 VULN-01 Verification - Rate Limiting and Account Lockout")
    print(f"  Target : {BASE_URL}")
    print(f"  User   : {TARGET_USERNAME}")
    print("  Rule   : 5 wrong passwords -> 6th request gets HTTP 429")
    print(SEPARATOR)

    wrong_results = phase1_wrong_attempts()
    correct_result = phase2_correct_attempt()
    phase3_summary(wrong_results, correct_result)
    phase4_db_evidence()

    print()
    print(SEPARATOR)
    print("  Done. Take screenshots of the terminal sections above.")
    print(SEPARATOR)


if __name__ == "__main__":
    main()
