from __future__ import annotations

from flask import Blueprint, current_app, render_template

from ..db import query_all, query_one
from ..security import current_user, require_login

bp = Blueprint("pages", __name__)


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
