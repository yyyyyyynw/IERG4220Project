from __future__ import annotations

import io
import time

import qrcode
from flask import (
    Blueprint, current_app, flash, jsonify, make_response, redirect,
    render_template, request, session, url_for,
)

from ..db import execute, query_all, query_one
from ..security import (
    SESSION_COOKIE, clear_throttle, create_session, current_user,
    generate_recovery_codes, generate_totp_secret, hash_password,
    hash_recovery_code, is_throttled, log_event, now, provisioning_uri,
    record_failure, require_login, revoke_session, set_session_cookie,
    validate_password, verify_password, verify_totp,
)

bp = Blueprint("auth", __name__)


def qr_data_uri(text: str) -> str:
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    import base64
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


def _full_user(user_id: int):
    return query_one("SELECT * FROM users WHERE id = ?", (user_id,))


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    confirm = request.form.get("confirm") or ""

    error = None
    if not username or len(username) > 64 or not all(
        c.isalnum() or c in "._-" for c in username
    ):
        error = "Username must be 1-64 characters (letters, digits, . _ -)."
    elif password != confirm:
        error = "Passwords do not match."
    else:
        error = validate_password(password, username)

    if error is None and query_one("SELECT id FROM users WHERE username = ?", (username,)):
        error = "That username is already taken."

    if error:
        return render_template("register.html", error=error, username=username), 400

    secret = generate_totp_secret()
    user_id = execute(
        "INSERT INTO users(username, password_hash, totp_secret, totp_last_step,"
        " webauthn_user_id, created_at) VALUES (?,?,?,?,?,?)",
        (username, hash_password(password), secret, -1,
         __import__("secrets").token_bytes(16), now()),
    ).lastrowid

    codes = generate_recovery_codes(current_app.config["RECOVERY_CODE_COUNT"])
    from ..db import execute_many
    execute_many(
        "INSERT INTO recovery_codes(user_id, code_hash) VALUES (?,?)",
        [(user_id, hash_recovery_code(c)) for c in codes],
    )
    execute("UPDATE users SET recovery_generated_at = ? WHERE id = ?", (now(), user_id))

    token = create_session(user_id, "registration")
    session["new_recovery_codes"] = codes
    log_event("register", user_id=user_id, username=username,
              method="registration", success=True,
              detail="password + TOTP account created")

    resp = make_response(redirect(url_for("auth.enroll")))
    return set_session_cookie(resp, token)


@bp.get("/enroll")
@require_login
def enroll():
    user = _full_user(current_user()["user_id"])
    credentials = query_all(
        "SELECT * FROM credentials WHERE user_id = ? ORDER BY created_at", (user["id"],)
    )
    codes = session.pop("new_recovery_codes", None)
    uri = provisioning_uri(user["username"], user["totp_secret"])
    return render_template(
        "enroll.html", user=user, credentials=credentials,
        qr=qr_data_uri(uri), uri=uri, codes=codes,
    )


@bp.post("/enroll/recovery-codes")
@require_login
def regenerate_recovery_codes():
    user = _full_user(current_user()["user_id"])
    execute("DELETE FROM recovery_codes WHERE user_id = ?", (user["id"],))
    codes = generate_recovery_codes(current_app.config["RECOVERY_CODE_COUNT"])
    from ..db import execute_many
    execute_many(
        "INSERT INTO recovery_codes(user_id, code_hash) VALUES (?,?)",
        [(user["id"], hash_recovery_code(c)) for c in codes],
    )
    execute("UPDATE users SET recovery_generated_at = ? WHERE id = ?", (now(), user["id"]))
    log_event("recovery_codes_regenerated", user_id=user["id"],
              username=user["username"], method="recovery", success=True)
    credentials = query_all(
        "SELECT * FROM credentials WHERE user_id = ? ORDER BY created_at", (user["id"],)
    )
    uri = provisioning_uri(user["username"], user["totp_secret"])
    return render_template(
        "enroll.html", user=user, credentials=credentials,
        qr=qr_data_uri(uri), uri=uri, codes=codes,
    )


@bp.route("/login", methods=["GET"])
def login():
    return render_template("login.html")


@bp.post("/login/password")
def login_password():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    rate_key = f"{username}|{request.remote_addr}"

    if is_throttled("password", rate_key):
        log_event("password_login", username=username, method="password_totp",
                  success=False, detail="throttled")
        return render_template("login.html", error="Too many attempts. Try later."), 429

    row = query_one("SELECT * FROM users WHERE username = ?", (username,))
    if row is None or not verify_password(password, row["password_hash"]):
        record_failure("password", rate_key)
        log_event("password_login", username=username, method="password_totp",
                  success=False, detail="bad credentials")
        # Deliberately identical for unknown users and wrong passwords.
        return render_template("login.html", error="Invalid username or password."), 401

    clear_throttle("password", rate_key)
    session["pending_user_id"] = row["id"]
    session["pending_username"] = row["username"]
    session["pending_ts"] = time.time()
    log_event("password_ok", user_id=row["id"], username=row["username"],
              method="password_totp", success=True, detail="password step passed")
    return redirect(url_for("auth.login_totp"))


@bp.route("/login/totp", methods=["GET", "POST"])
def login_totp():
    pending_id = session.get("pending_user_id")
    pending_ts = session.get("pending_ts", 0)
    if not pending_id or time.time() - pending_ts > 300:
        session.pop("pending_user_id", None)
        return redirect(url_for("auth.login"))

    user = _full_user(pending_id)
    if user is None:
        session.pop("pending_user_id", None)
        return redirect(url_for("auth.login"))

    rate_key = f"{user['username']}|{request.remote_addr}"
    if is_throttled("totp", rate_key):
        log_event("totp_login", user_id=user["id"], username=user["username"],
                  method="password_totp", success=False, detail="throttled")
        return render_template(
            "totp.html", username=user["username"],
            error="Too many attempts. Try later."
        ), 429

    if request.method == "GET":
        return render_template("totp.html", username=user["username"])

    code = request.form.get("code") or ""
    ok, counter, reason = verify_totp(
        user["totp_secret"], code, user["totp_last_step"],
        window=current_app.config["TOTP_WINDOW"],
        digits=current_app.config["TOTP_DIGITS"],
        enforce_replay=current_app.config["TOTP_REPLAY_PROTECTION"],
    )
    if not ok:
        record_failure("totp", rate_key)
        log_event("totp_login", user_id=user["id"], username=user["username"],
                  method="password_totp", success=False, detail=reason)
        return render_template(
            "totp.html", username=user["username"],
            error="Invalid or already-used code."
        ), 401

    clear_throttle("totp", rate_key)
    execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (counter, user["id"]))
    session.pop("pending_user_id", None)
    session.pop("pending_username", None)
    session.pop("pending_ts", None)
    token = create_session(user["id"], "password_totp")
    log_event("login", user_id=user["id"], username=user["username"],
              method="password_totp", success=True,
              detail=f"totp counter={counter}")
    resp = make_response(redirect(url_for("pages.dashboard")))
    return set_session_cookie(resp, token)


@bp.post("/logout")
def logout():
    token = request.cookies.get(SESSION_COOKIE)
    user = current_user()
    if token:
        revoke_session(token)
    if user:
        log_event("logout", user_id=user["user_id"], username=user["username"],
                  method=user["session_method"], success=True)
    resp = make_response(redirect(url_for("pages.index")))
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@bp.get("/api/me")
@require_login
def api_me():
    user = current_user()
    creds = query_all(
        "SELECT credential_id, kind, label, sign_count, backup_eligible,"
        " backup_state, created_at, last_used FROM credentials WHERE user_id = ?",
        (user["user_id"],),
    )
    return jsonify(
        ok=True,
        username=user["username"],
        method=user["session_method"],
        credentials=[dict(c) for c in creds],
    )
