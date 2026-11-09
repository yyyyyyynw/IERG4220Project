"""Test-only control surface.

Every endpoint is disabled unless ``AUTHLAB_LAB=1`` and requires the
``X-AuthLab-Lab`` token.  This keeps the instrumentation out of the normal
authentication surface while giving the experiment harness ground truth
(TOTP secrets, counters, session state) without scraping the UI.
"""
from __future__ import annotations

from functools import wraps

from flask import Blueprint, abort, current_app, jsonify, request

from ..db import execute, query_all, query_one
from ..security import json_body, now, verify_totp

bp = Blueprint("lab", __name__)


def lab_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_app.config["LAB_MODE"]:
            abort(404)
        if request.headers.get("X-AuthLab-Lab") != current_app.config["LAB_TOKEN"]:
            abort(401)
        return view(*args, **kwargs)
    return wrapper


@bp.get("/lab/health")
@lab_required
def health():
    return jsonify(ok=True, rp_id=current_app.config["RP_ID"],
                   origins=current_app.config["ORIGINS"],
                   counter_policy=current_app.config["COUNTER_POLICY"],
                   totp_replay_protection=current_app.config["TOTP_REPLAY_PROTECTION"])


@bp.get("/lab/state")
@lab_required
def state():
    username = request.args.get("username", "")
    user = query_one("SELECT * FROM users WHERE username = ?", (username,))
    if user is None:
        return jsonify(ok=False, error="not_found"), 404
    creds = query_all(
        "SELECT id, credential_id, kind, label, sign_count, backup_eligible,"
        " backup_state, created_at, last_used FROM credentials WHERE user_id = ?",
        (user["id"],),
    )
    sessions = query_all(
        "SELECT method, created_at, expires_at, revoked FROM sessions WHERE user_id = ?",
        (user["id"],),
    )
    codes = query_one(
        "SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
        (user["id"],),
    )["n"]
    audit = query_all(
        "SELECT ts, event, method, success, detail FROM audit_log WHERE user_id = ?"
        " ORDER BY ts DESC LIMIT 30", (user["id"],),
    )
    return jsonify(
        ok=True, username=user["username"], user_id=user["id"],
        totp_secret=user["totp_secret"], totp_last_step=user["totp_last_step"],
        credentials=[dict(c) for c in creds],
        sessions=[dict(s) for s in sessions],
        recovery_codes_left=codes,
        audit=[dict(a) for a in audit],
    )


@bp.post("/lab/totp/verify")
@lab_required
def totp_verify():
    """Exercise the TOTP verifier with an explicit policy.

    Used to compare a hardened verifier (monotonic per-user counter) with a
    naive one that accepts any code in the time window.  ``update=False``
    allows repeated checks without mutating state.
    """
    data = json_body()
    username = (data.get("username") or "").strip()
    user = query_one("SELECT * FROM users WHERE username = ?", (username,))
    if user is None:
        return jsonify(ok=False, error="not_found"), 404
    code = str(data.get("code") or "")
    enforce = bool(data.get("enforce_replay", True))
    update = bool(data.get("update", True))
    ok, counter, reason = verify_totp(
        user["totp_secret"], code, user["totp_last_step"],
        window=current_app.config["TOTP_WINDOW"],
        digits=current_app.config["TOTP_DIGITS"],
        enforce_replay=enforce,
    )
    if ok and update and counter is not None:
        execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (counter, user["id"]))
    return jsonify(ok=ok, counter=counter, reason=reason,
                   last_step=user["totp_last_step"], enforce_replay=enforce)


@bp.post("/lab/credentials/mark-synced")
@lab_required
def mark_synced():
    """Model the cloud sync fabric for a platform credential.

    Chrome's virtual authenticator always attests BE=0.  To exercise the
    synced-passkey path we re-import the credential onto a second virtual
    authenticator with BE=1/BS=1 and mark the server-side record accordingly.
    This is a simulation of a sync provider, not a real cloud service.
    """
    data = json_body()
    credential_id = data.get("credential_id")
    row = query_one("SELECT * FROM credentials WHERE credential_id = ?",
                    (credential_id,))
    if row is None:
        return jsonify(ok=False, error="not_found"), 404
    execute(
        "UPDATE credentials SET backup_eligible = 1, backup_state = 1,"
        " label = 'Synced passkey' WHERE id = ?", (row["id"],),
    )
    return jsonify(ok=True, credential_id=credential_id,
                   backup_eligible=True, backup_state=True, updated_at=now())


@bp.post("/lab/session/revoke")
@lab_required
def revoke_sessions():
    data = json_body()
    user = query_one("SELECT * FROM users WHERE username = ?",
                     (data.get("username"),))
    if user is None:
        return jsonify(ok=False, error="not_found"), 404
    cur = execute("UPDATE sessions SET revoked = 1 WHERE user_id = ?", (user["id"],))
    return jsonify(ok=True, revoked=cur.rowcount)
