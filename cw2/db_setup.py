"""
Initialise the CW2 SQLite database with secure seed data.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from auth import DEMO_TOTP_SECRETS, hash_password

BASE_DIR = Path(__file__).resolve().parent
DB_DIR = BASE_DIR / "database"
LOG_DIR = BASE_DIR / "logs"
DB_PATH = DB_DIR / "portal.db"


def init_db() -> None:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    if DB_PATH.exists():
        DB_PATH.unlink()

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")

    conn.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('student', 'admin')),
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            student_id TEXT UNIQUE,
            totp_secret TEXT NOT NULL
        );

        CREATE TABLE grades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL,
            module_code TEXT NOT NULL,
            module_name TEXT NOT NULL,
            academic_year TEXT NOT NULL,
            mark INTEGER NOT NULL,
            grade TEXT NOT NULL,
            FOREIGN KEY (student_id) REFERENCES users(student_id) ON DELETE CASCADE
        );

        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor_username TEXT,
            actor_role TEXT,
            action TEXT NOT NULL,
            target TEXT,
            success INTEGER NOT NULL,
            ip_address TEXT,
            detail TEXT
        );

        CREATE TABLE login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username TEXT,
            success INTEGER NOT NULL,
            ip_address TEXT,
            detail TEXT
        );

        CREATE INDEX idx_users_username ON users(username);
        CREATE INDEX idx_users_student_id ON users(student_id);
        CREATE INDEX idx_grades_student_id ON grades(student_id);
        CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
        CREATE INDEX idx_login_attempts_timestamp ON login_attempts(timestamp);
        """
    )

    users = [
        (
            1,
            "alice",
            hash_password("password123"),
            "student",
            "Alice Zhang",
            "alice@university.ac.uk",
            "S001",
            DEMO_TOTP_SECRETS["alice"],
        ),
        (
            2,
            "bob",
            hash_password("letmein"),
            "student",
            "Bob Smith",
            "bob@university.ac.uk",
            "S002",
            DEMO_TOTP_SECRETS["bob"],
        ),
        (
            3,
            "admin",
            hash_password("admin123"),
            "admin",
            "Admin User",
            "admin@university.ac.uk",
            None,
            DEMO_TOTP_SECRETS["admin"],
        ),
    ]

    grades = [
        ("S001", "ELEC0138", "Signals and Systems", "2025/26", 72, "A-"),
        ("S001", "ELEC0140", "Digital Design", "2025/26", 68, "B+"),
        ("S001", "COMP0016", "Systems Engineering", "2025/26", 81, "A"),
        ("S001", "COMP0025", "Security and Privacy", "2025/26", 55, "C+"),
        ("S002", "ELEC0138", "Signals and Systems", "2025/26", 60, "B"),
        ("S002", "ELEC0140", "Digital Design", "2025/26", 45, "D"),
        ("S002", "COMP0016", "Systems Engineering", "2025/26", 73, "A-"),
    ]

    conn.executemany(
        """
        INSERT INTO users (
            id, username, password_hash, role, full_name,
            email, student_id, totp_secret
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        users,
    )
    conn.executemany(
        """
        INSERT INTO grades (
            student_id, module_code, module_name, academic_year, mark, grade
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        grades,
    )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Initialised CW2 SQLite database at {DB_PATH}")
