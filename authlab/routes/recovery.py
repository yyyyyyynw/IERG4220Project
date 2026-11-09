from __future__ import annotations

import secrets

from flask import (
    Blueprint, current_app, flash, jsonify, make_response, redirect,
    render_template, request, url_for,
)

from ..db import execute, query_all, query_one
from ..security import (
    clear_throttle, create_session, current_user, generate_recovery_codes,
    generate_totp_secret, hash_password, hash_recovery_code, is_throttled,
    log_event, normalize_recovery_code, now, record_failure, require_login,
    revoke_all_sessions, set_session_cookie, sha256_hex, validate_password,
    verify_recovery_code,
)
from .auth import qr_data_uri
from ..security import provisioning_uri

bp = Blueprint("recovery", __name__)


def _user_by_username(username: str):
    return query_one("SELECT * FROM users WHERE username = ?", (username,))


@bp.route("/recovery", methods=["GET", "POST"])
def recovery_home():
    if request.method == "GET":
        return render_template("recovery.html")

    username = (request.form.get("username") or "").strip()
    user = _user_by_username(username)
    reset_link = None
    # Always show the same message, whether or not the account exists.
    message = "If that account exists, a reset link has been sent."
    if user is not None:
        token = secrets.token_urlsafe(32)
        ts = now()
        execute(
            "INSERT INTO recovery_tokens(user_id, token_hash, created_at, expires_at)"
            " VALUES (?,?,?,?)",
            (user["id"], sha256_hex(token), ts,
             ts + current_app.config["RECOVERY_TOKEN_TTL"]),
        )
        log_event("recovery_request", user_id=user["id"], username=user["username"],
                  method="email_token", success=True, detail="reset token issued")
        if current_app.config["SHOW_RECOVERY_LINK"]:
            reset_link = url_for("recovery.reset", token=token, _external=True)
    return render_template(
        "recovery.html", message=message, reset_link=reset_link, username=username
    )


@bp.route("/recovery/reset/<token>", methods=["GET", "POST"])
def reset(token: str):
    token_hash = sha256_hex(token)
    row = query_one(
        "SELECT rt.*, u.username FROM recovery_tokens rt"
        " JOIN users u ON u.id = rt.user_id"
        " WHERE rt.token_hash = ? AND rt.used_at IS NULL AND rt.expires_at > ?",
        (token_hash, now()),
    )
    if row is None:
        return render_template("recovery.html",
                               error="This reset link is invalid, used, or expired."), 400

    if request.method == "GET":
        return render_template("reset.html", token=token, username=row["username"])

    password = request.form.get("password") or ""
    confirm = request.form.get("confirm") or ""
    error = None
    if password != confirm:
        error = "Passwords do not match."
    else:
        error = validate_password(password, row["username"])
    if error:
        return render_template("reset.html", token=token,
                               username=row["username"], error=error), 400

    # Consume the token atomically before changing anything.
    cur = execute(
        "UPDATE recovery_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL",
        (now(), row["id"]),
    )
    if cur.rowcount != 1:
        return render_template("recovery.html",
                               error="This reset link has already been used."), 400

    new_secret = generate_totp_secret()
    execute(
        "UPDATE users SET password_hash = ?, totp_secret = ?, totp_last_step = -1"
        " WHERE id = ?",
        (hash_password(password), new_secret, row["user_id"]),
    )
    # Invalidate every existing session and every old recovery code.
    revoke_all_sessions(row["user_id"])
    execute("DELETE FROM recovery_codes WHERE user_id = ?", (row["user_id"],))
    log_event("password_reset", user_id=row["user_id"], username=row["username"],
              method="email_token", success=True,
              detail="password changed; all sessions revoked; TOTP rotated")
    uri = provisioning_uri(row["username"], new_secret)
    return render_template(
        "reset_done.html", username=row["username"],
        qr=qr_data_uri(uri), secret=new_secret,
    )


@bp.post("/recovery/code")
def recovery_code_login():
    username = (request.form.get("username") or "").strip()
    code = request.form.get("code") or ""
    rate_key = f"{username}|{request.remote_addr}"
    if is_throttled("recovery_code", rate_key):
        log_event("recovery_code_login", username=username,
                  method="recovery_code", success=False, detail="throttled")
        return render_template(
            "recovery.html", error="Too many attempts. Try later."
        ), 429
    user = _user_by_username(username)
    if user is None:
        record_failure("recovery_code", rate_key)
        log_event("recovery_code_login", username=username, method="recovery_code",
                  success=False, detail="unknown user")
        return render_template("recovery.html",
                               error="Invalid username or recovery code."), 401

    rows = query_all(
        "SELECT * FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
        (user["id"],),
    )
    matched = None
    for row in rows:
        if verify_recovery_code(code, row["code_hash"]):
            matched = row
            break
    if matched is None:
        record_failure("recovery_code", rate_key)
        log_event("recovery_code_login", user_id=user["id"], username=username,
                  method="recovery_code", success=False, detail="no matching code")
        return render_template("recovery.html",
                               error="Invalid username or recovery code."), 401

    cur = execute(
        "UPDATE recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL",
        (now(), matched["id"]),
    )
    if cur.rowcount != 1:
        return render_template("recovery.html",
                               error="That recovery code has already been used."), 401

    clear_throttle("recovery_code", rate_key)
    token = create_session(user["id"], "recovery_code")
    log_event("recovery_code_login", user_id=user["id"], username=username,
              method="recovery_code", success=True,
              detail="single-use recovery code accepted")
    resp = redirect(url_for("pages.dashboard"))
    return set_session_cookie(resp, token)


@bp.post("/recovery/change-password")
@require_login
def recovery_change_password():
    user = current_user()
    if user["session_method"] not in ("recovery_code", "registration"):
        return jsonify(ok=False, error="recovery_session_required"), 403
    password = request.form.get("password") or ""
    confirm = request.form.get("confirm") or ""
    error = None
    if password != confirm:
        error = "Passwords do not match."
    else:
        error = validate_password(password, user["username"])
    if error:
        flash(error, "error")
        return redirect(url_for("pages.dashboard"))

    new_secret = generate_totp_secret()
    execute(
        "UPDATE users SET password_hash = ?, totp_secret = ?, totp_last_step = -1"
        " WHERE id = ?",
        (hash_password(password), new_secret, user["user_id"]),
    )
    # Changing a password after recovery must invalidate every session that
    # existed before the recovery event, including a possible attacker
    # session.  A fresh session is issued for the current browser so the user
    # can finish enrolling the rotated TOTP secret.
    revoke_all_sessions(user["user_id"])
    token = create_session(user["user_id"], "recovery_code")
    log_event("password_changed", user_id=user["user_id"],
              username=user["username"], method=user["session_method"],
              success=True,
              detail="password and TOTP rotated after recovery; "
                     "all prior sessions revoked")
    uri = provisioning_uri(user["username"], new_secret)
    resp = make_response(render_template(
        "reset_done.html", username=user["username"],
        qr=qr_data_uri(uri), secret=new_secret,
    ))
    return set_session_cookie(resp, token)


@bp.post("/recovery/revoke-all")
@require_login
def revoke_everything():
    user = current_user()
    execute("DELETE FROM credentials WHERE user_id = ?", (user["user_id"],))
    execute("DELETE FROM recovery_codes WHERE user_id = ?", (user["user_id"],))
    n = revoke_all_sessions(user["user_id"])
    log_event("revoke_all", user_id=user["user_id"], username=user["username"],
              method=user["session_method"], success=True,
              detail=f"all credentials and {n} sessions revoked")
    resp = redirect(url_for("pages.index"))
    resp.delete_cookie("authlab_session", path="/")
    return resp


@bp.get("/recovery/status")
@require_login
def recovery_status():
    user = current_user()
    total = query_one("SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ?",
                      (user["user_id"],))["n"]
    left = query_one(
        "SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
        (user["user_id"],),
    )["n"]
    creds = query_all(
        "SELECT kind, label, backup_eligible, backup_state FROM credentials"
        " WHERE user_id = ?", (user["user_id"],),
    )
    return jsonify(
        ok=True, username=user["username"], method=user["session_method"],
        recovery_codes_total=total, recovery_codes_left=left,
        credentials=[dict(c) for c in creds],
    )
