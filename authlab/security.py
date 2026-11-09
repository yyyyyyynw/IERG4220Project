"""Passwords, TOTP, sessions, and small crypto helpers.

Password hashing uses scrypt.  TOTP is implemented directly against RFC 6238
so that the replay-window behaviour is explicit and testable (rather than
hidden inside a third-party helper).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
from functools import wraps

from flask import current_app, g, jsonify, redirect, request, url_for

from .db import execute, query_one

# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------

def now() -> float:
    return time.time()


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def constant_time(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LEN = 32


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_LEN,
    )
    return "scrypt${}${}${}${}${}".format(
        SCRYPT_N, SCRYPT_R, SCRYPT_P, b64e(salt), b64e(digest)
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, digest_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = b64d(salt_b64)
        expected = b64d(digest_b64)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


COMMON_PASSWORDS = {
    "password", "password1", "12345678", "123456789", "qwerty123",
    "letmein", "welcome", "admin123", "iloveyou", "monkey123",
}


def validate_password(password: str, username: str) -> str | None:
    if len(password) < 10:
        return "Password must be at least 10 characters."
    if len(password) > 256:
        return "Password is too long."
    if password.lower() in COMMON_PASSWORDS:
        return "Password is too common."
    if username and username.lower() in password.lower():
        return "Password must not contain the username."
    return None


# ---------------------------------------------------------------------------
# TOTP (RFC 6238)
# ---------------------------------------------------------------------------

TOTP_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def generate_totp_secret(length: int = 20) -> str:
    raw = secrets.token_bytes(length)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _totp_key(secret: str) -> bytes:
    padded = secret.upper()
    padded += "=" * ((8 - len(padded) % 8) % 8)
    return base64.b32decode(padded, casefold=True)


def totp_at(secret: str, at_time: float | None = None,
            step: int = 30, digits: int = 6) -> tuple[str, int]:
    """Return (code, counter) for the time step containing ``at_time``."""
    timestamp = time.time() if at_time is None else at_time
    counter = int(timestamp // step)
    digest = hmac.new(
        _totp_key(secret), struct.pack(">Q", counter), hashlib.sha1
    ).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits), counter


def totp_at_counter(secret: str, counter: int, digits: int = 6) -> str:
    digest = hmac.new(
        _totp_key(secret), struct.pack(">Q", counter), hashlib.sha1
    ).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def verify_totp(secret: str, code: str, last_step: int = -1,
                window: int = 1, digits: int = 6,
                enforce_replay: bool = True,
                at_time: float | None = None) -> tuple[bool, int | None, str]:
    """Verify a TOTP code.

    Returns ``(ok, counter, reason)``.  Replay protection is a *server-side*
    property: the same (code, counter) is rejected once ``last_step`` has
    reached it.  Without it, a phished or observed code remains valid for the
    rest of its window.
    """
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != digits:
        return False, None, "malformed"
    timestamp = time.time() if at_time is None else at_time
    current = int(timestamp // 30)
    for offset in range(-window, window + 1):
        candidate = current + offset
        expected = totp_at_counter(secret, candidate, digits)
        if constant_time(expected, code):
            if enforce_replay and candidate <= last_step:
                return False, candidate, "replayed"
            return True, candidate, "ok"
    return False, None, "mismatch"


def provisioning_uri(username: str, secret: str, issuer: str = "AuthLab") -> str:
    from urllib.parse import quote
    return (
        f"otpauth://totp/{quote(issuer)}:{quote(username)}"
        f"?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1"
        f"&digits=6&period=30"
    )


# ---------------------------------------------------------------------------
# Recovery material
# ---------------------------------------------------------------------------

RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def generate_recovery_codes(count: int = 10) -> list[str]:
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(8))
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def normalize_recovery_code(code: str) -> str:
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def hash_recovery_code(code: str) -> str:
    normalized = normalize_recovery_code(code)
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        normalized.encode("ascii"), salt=salt, n=2**14, r=8, p=1, dklen=32
    )
    return f"scrypt${b64e(salt)}${b64e(digest)}"


def verify_recovery_code(code: str, stored: str) -> bool:
    try:
        scheme, salt_b64, digest_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = b64d(salt_b64)
        expected = b64d(digest_b64)
        actual = hashlib.scrypt(
            normalize_recovery_code(code).encode("ascii"),
            salt=salt, n=2**14, r=8, p=1, dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

SESSION_COOKIE = "authlab_session"


def new_session_token() -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    return token, sha256_hex(token)


def create_session(user_id: int, method: str) -> str:
    token, token_hash = new_session_token()
    ts = now()
    execute(
        "INSERT INTO sessions(token_hash, user_id, method, created_at, expires_at,"
        " revoked, ip, user_agent) VALUES (?,?,?,?,?,0,?,?)",
        (
            token_hash,
            user_id,
            method,
            ts,
            ts + current_app.config["SESSION_TTL"],
            request.remote_addr,
            request.headers.get("User-Agent", "")[:300],
        ),
    )
    return token


def set_session_cookie(response, token: str):
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=current_app.config["SESSION_TTL"],
        httponly=True,
        samesite="Lax",
        secure=request.is_secure,
        path="/",
    )
    return response


def current_user():
    if "current_user" in g:
        return g.current_user
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        g.current_user = None
        return None
    row = query_one(
        """
        SELECT u.id AS user_id, u.username, u.totp_secret, u.totp_last_step,
               u.webauthn_user_id, u.created_at, u.recovery_generated_at,
               s.method AS session_method, s.token_hash, s.expires_at AS session_expires
          FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ? AND s.revoked = 0 AND s.expires_at > ?
        """,
        (sha256_hex(token), now()),
    )
    g.current_user = row
    return row


def require_login(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            if request.path.startswith(("/webauthn", "/lab", "/api")) or request.is_json:
                return jsonify(ok=False, error="unauthorized"), 401
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapper


def revoke_session(token: str) -> None:
    execute("UPDATE sessions SET revoked = 1 WHERE token_hash = ?", (sha256_hex(token),))


def revoke_all_sessions(user_id: int) -> int:
    cur = execute("UPDATE sessions SET revoked = 1 WHERE user_id = ? AND revoked = 0",
                  (user_id,))
    return cur.rowcount


# ---------------------------------------------------------------------------
# Audit log, throttling, JSON helpers
# ---------------------------------------------------------------------------

def log_event(event: str, *, user_id=None, username=None, method=None,
              success: bool = True, detail: str = "") -> None:
    execute(
        "INSERT INTO audit_log(ts, event, user_id, username, method, success, ip, detail)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (
            now(), event, user_id, username, method, 1 if success else 0,
            request.remote_addr, detail[:2000],
        ),
    )


def throttle_key(prefix: str, identifier: str) -> str:
    return f"{prefix}:{identifier.lower()}"


def is_throttled(prefix: str, identifier: str) -> bool:
    key = throttle_key(prefix, identifier)
    row = query_one("SELECT * FROM throttle WHERE key = ?", (key,))
    if not row:
        return False
    if now() - row["window_start"] > current_app.config["LOGIN_WINDOW"]:
        execute("DELETE FROM throttle WHERE key = ?", (key,))
        return False
    return row["count"] >= current_app.config["MAX_LOGIN_ATTEMPTS"]


def record_failure(prefix: str, identifier: str) -> None:
    key = throttle_key(prefix, identifier)
    row = query_one("SELECT * FROM throttle WHERE key = ?", (key,))
    ts = now()
    if row is None or ts - row["window_start"] > current_app.config["LOGIN_WINDOW"]:
        execute(
            "INSERT INTO throttle(key, count, window_start) VALUES (?,1,?)"
            " ON CONFLICT(key) DO UPDATE SET count=1, window_start=excluded.window_start",
            (key, ts),
        )
    else:
        execute("UPDATE throttle SET count = count + 1 WHERE key = ?", (key,))


def clear_throttle(prefix: str, identifier: str) -> None:
    execute("DELETE FROM throttle WHERE key = ?", (throttle_key(prefix, identifier),))


def store_flow(user_id: int | None, purpose: str, kind: str,
               challenge: str, rp_id: str, origin: str | None = None) -> str:
    """Persist a WebAuthn challenge and return an opaque flow id.

    A flow id (rather than a cookie) is used so that the phishing proxy can
    relay a challenge exactly as a real reverse proxy would.
    """
    flow_id = secrets.token_urlsafe(24)
    ts = now()
    execute(
        "INSERT INTO flows(flow_id, user_id, purpose, kind, challenge, rp_id,"
        " origin, created_at, expires_at, used) VALUES (?,?,?,?,?,?,?,?,?,0)",
        (flow_id, user_id, purpose, kind, challenge, rp_id, origin,
         ts, ts + current_app.config["FLOW_TTL"]),
    )
    return flow_id


def consume_flow(flow_id: str, purpose: str):
    """Atomically mark a flow used; return the row or None."""
    if not flow_id:
        return None
    row = query_one("SELECT * FROM flows WHERE flow_id = ?", (flow_id,))
    if row is None:
        return None
    if row["used"] or row["expires_at"] < now() or row["purpose"] != purpose:
        return None
    cur = execute(
        "UPDATE flows SET used = 1 WHERE flow_id = ? AND used = 0", (flow_id,)
    )
    if cur.rowcount != 1:
        return None
    return row


def json_body() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def parse_client_data(credential: dict) -> dict:
    """Decode clientDataJSON from a serialized WebAuthn credential."""
    from webauthn.helpers import base64url_to_bytes
    try:
        raw = base64url_to_bytes(credential["response"]["clientDataJSON"])
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}
