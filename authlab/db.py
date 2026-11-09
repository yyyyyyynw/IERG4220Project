"""SQLite persistence for AuthLab."""
from __future__ import annotations

import sqlite3

from flask import current_app, g

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    username              TEXT NOT NULL UNIQUE,
    password_hash         TEXT NOT NULL,
    totp_secret           TEXT NOT NULL,
    totp_last_step        INTEGER NOT NULL DEFAULT -1,
    webauthn_user_id      BLOB NOT NULL,
    created_at            REAL NOT NULL,
    recovery_generated_at REAL
);

CREATE TABLE IF NOT EXISTS credentials (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id     TEXT NOT NULL UNIQUE,
    public_key        BLOB NOT NULL,
    sign_count        INTEGER NOT NULL DEFAULT 0,
    transports        TEXT,
    aaguid            TEXT,
    kind              TEXT NOT NULL CHECK (kind IN ('platform', 'roaming')),
    backup_eligible   INTEGER NOT NULL DEFAULT 0,
    backup_state      INTEGER NOT NULL DEFAULT 0,
    label             TEXT,
    created_at        REAL NOT NULL,
    last_used         REAL
);

CREATE TABLE IF NOT EXISTS flows (
    flow_id     TEXT PRIMARY KEY,
    user_id     INTEGER,
    purpose     TEXT NOT NULL,
    kind        TEXT,
    challenge   TEXT NOT NULL,
    rp_id       TEXT NOT NULL,
    origin      TEXT,
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method      TEXT NOT NULL,
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0,
    ip          TEXT,
    user_agent  TEXT
);

CREATE TABLE IF NOT EXISTS recovery_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    REAL
);

CREATE TABLE IF NOT EXISTS recovery_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    used_at     REAL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    event    TEXT NOT NULL,
    user_id  INTEGER,
    username TEXT,
    method   TEXT,
    success  INTEGER NOT NULL,
    ip       TEXT,
    detail   TEXT
);

CREATE TABLE IF NOT EXISTS throttle (
    key          TEXT PRIMARY KEY,
    count        INTEGER NOT NULL,
    window_start REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_flows_expiry ON flows(expires_at);
"""


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


def init_db(path: str) -> None:
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["DB_PATH"])
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query_one(sql: str, params: tuple = ()):
    return get_db().execute(sql, params).fetchone()


def query_all(sql: str, params: tuple = ()):
    return get_db().execute(sql, params).fetchall()


def execute(sql: str, params: tuple = ()):
    db = get_db()
    cur = db.execute(sql, params)
    db.commit()
    return cur


def execute_many(sql: str, rows):
    db = get_db()
    cur = db.executemany(sql, rows)
    db.commit()
    return cur
