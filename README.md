# ELEC0138 Security and Privacy - Student Grade Portal

## Project Structure

```text
grade-portal/
|- cw1/                        # Vulnerable CW1 version
|  |- app.py
|  |- init_db.py
|  |- templates/
|  `- static/
|- cw2/                        # Defended CW2 version
|  |- app.py                   # Rate limiting + ownership checks + MFA flow
|  |- auth.py                  # JWT / TOTP helpers
|  |- db_setup.py
|  |- templates/               # Dedicated CW2 pages
|  `- static/                  # style.css + auth.js + logger.js
|- attack/                     # Attack / verification scripts
|- screenshots/
`- README.md
```

## Quick Start (CW1 - Vulnerable Version)

```bash
cd cw1
python -m pip install -r requirements.txt
python init_db.py
python app.py                   # http://127.0.0.1:5000
```

## Quick Start (CW2 - Defended Version)

```bash
cd cw2
python -m pip install -r requirements.txt
python db_setup.py
python app.py                   # http://127.0.0.1:5000
```

## Run Attack Scripts

Use the version-specific attack files below so the evidence in the report is
clearly separated between CW1 and CW2.

### CW1 attack scripts

```bash
# In a second terminal, ensure CW1 is already running on http://127.0.0.1:5000
cd attack
python brute_force_cw1.py
python idor_demo_cw1.py
```

### CW2 verification scripts

```bash
# In a second terminal, ensure CW2 is already running on http://127.0.0.1:5000
cd attack
python brute_force_cw2.py
python idor_demo_cw2.py
```

## Test Accounts

| Username | Password    | Role    | Student ID |
|----------|-------------|---------|------------|
| alice    | password123 | student | S001       |
| bob      | letmein     | student | S002       |
| admin    | admin123    | admin   | NULL       |

## CW1 Vulnerabilities

- `VULN-01`: `POST /login` has no rate limiting or lockout
- `VULN-02`: `GET /profile` and `GET /results` allow IDOR access

## CW2 Defences

- Password verification and MFA are split across `POST /login` and `POST /login/mfa`
- Login failures trigger account lockout and `/login` rate limiting
- `/profile` and `/results` enforce student ownership, with admin override
- The frontend uses shared `auth.js` handling for 401 redirects, 403 warning banners, and session expiry alerts


