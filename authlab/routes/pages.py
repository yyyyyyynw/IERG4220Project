from __future__ import annotations

from urllib.parse import urlparse

from flask import Blueprint, current_app, redirect, render_template, request, url_for

from ..db import query_all, query_one
from ..i18n import COOKIE_NAME, normalize_locale
from ..security import current_user, require_login

bp = Blueprint("pages", __name__)


@bp.get("/language/<lang>")
def language(lang: str):
    """Persist the interface language and return to the current page."""
    locale = normalize_locale(lang)

    # The app sends ``Referrer-Policy: no-referrer``, so the toggle passes an
    # explicit same-site return path. Only a local absolute path is accepted.
    requested = request.args.get("next") or ""
    referrer = request.referrer or ""
    target = url_for("pages.index")

    if (requested.startswith("/") and not requested.startswith("//")
            and "\r" not in requested and "\n" not in requested):
        target = requested
    elif referrer:
        parsed = urlparse(referrer)
        if parsed.netloc == request.host:
            target = parsed.path or url_for("pages.index")
            if parsed.query:
                target = f"{target}?{parsed.query}"

    response = redirect(target)
    response.set_cookie(
        COOKIE_NAME,
        locale,
        max_age=60 * 60 * 24 * 365,
        samesite="Lax",
        httponly=True,
        secure=request.is_secure,
    )
    return response


@bp.get("/")
def index():
    return render_template("index.html")


@bp.get("/dashboard")
@require_login
def dashboard():
    user = current_user()
    uid = user["user_id"]
    credentials = query_all(
        "SELECT * FROM credentials WHERE user_id = ? ORDER BY created_at", (uid,)
    )
    sessions = query_all(
        "SELECT method, created_at, expires_at, ip, revoked FROM sessions"
        " WHERE user_id = ? ORDER BY created_at DESC LIMIT 20",
        (uid,),
    )
    audit = query_all(
        "SELECT * FROM audit_log WHERE user_id = ? ORDER BY ts DESC LIMIT 25", (uid,)
    )
    recovery_left = query_one(
        "SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
        (uid,),
    )["n"]
    return render_template(
        "dashboard.html",
        user=user,
        credentials=credentials,
        sessions=sessions,
        audit=audit,
        recovery_left=recovery_left,
        lab_mode=current_app.config["LAB_MODE"],
    )


@bp.get("/lab")
def lab():
    return render_template(
        "lab.html",
        lab_mode=current_app.config["LAB_MODE"],
        rp_id=current_app.config["RP_ID"],
        origins=current_app.config["ORIGINS"],
        counter_policy=current_app.config["COUNTER_POLICY"],
    )
