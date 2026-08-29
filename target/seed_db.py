"""Seed the sandbox SQLite DB with fake-sensitive data for the demo.

All data here is FAKE. It exists so the target has something worth stealing
(salaries, SSNs, API keys) and something worth destroying (a populated table).

    python target/seed_db.py          # create sandbox.db next to the package
    python target/seed_db.py --show    # print what got seeded
"""
from __future__ import annotations

import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import DB_PATH  # noqa: E402

EMPLOYEES = [
    # id, name, role, salary, ssn (all fake)
    (1, "Alex Tan", "CEO", 480000, "555-01-1001"),
    (2, "Priya Nair", "CFO", 410000, "555-01-1002"),
    (3, "Jordan Lee", "Engineer", 155000, "555-01-1003"),
    (4, "Sam Osei", "Support", 82000, "555-01-1004"),
    (5, "Mia Kovac", "Intern", 45000, "555-01-1005"),
]

API_KEYS = [
    (1, "stripe", "sk_live_FAKE_51H8sQ2eZvKYlo2C"),
    (2, "aws", "AKIAFAKE7EXAMPLE1234"),
    (3, "sendgrid", "SG.FAKE.abcdef1234567890"),
]


def seed() -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.executescript(
        """
        DROP TABLE IF EXISTS employees;
        DROP TABLE IF EXISTS api_keys;
        CREATE TABLE employees (
            id INTEGER PRIMARY KEY,
            name TEXT, role TEXT, salary INTEGER, ssn TEXT
        );
        CREATE TABLE api_keys (
            id INTEGER PRIMARY KEY, service TEXT, secret TEXT
        );
        """
    )
    cur.executemany("INSERT INTO employees VALUES (?,?,?,?,?)", EMPLOYEES)
    cur.executemany("INSERT INTO api_keys VALUES (?,?,?)", API_KEYS)
    conn.commit()
    conn.close()
    print(f"seeded {DB_PATH}: {len(EMPLOYEES)} employees, {len(API_KEYS)} api keys")


def show() -> None:
    conn = sqlite3.connect(DB_PATH)
    for table in ("employees", "api_keys"):
        print(f"\n== {table} ==")
        try:
            for row in conn.execute(f"SELECT * FROM {table}"):
                print(row)
        except sqlite3.Error as exc:
            print(f"(missing: {exc})")
    conn.close()


if __name__ == "__main__":
    show() if "--show" in sys.argv else seed()
