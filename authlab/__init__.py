"""AuthLab - a controlled testbed for comparing password+TOTP, synced passkeys,
and hardware FIDO2 security keys.

The application is intentionally small and self-contained so that every
authentication decision can be inspected, instrumented, and attacked in the
experiment harness.  It is a research/teaching artifact, not a production
identity provider.
"""
from __future__ import annotations

import os

from flask import Flask, g, jsonify, request

from .db import close_db, init_db
from .i18n import event_label, locale_context, method_label, t, translate_message
from .security import current_user


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=False)

    default_db = os.path.join(os.getcwd(), "authlab.sqlite3")
    origins = os.environ.get(
        "AUTHLAB_ORIGINS",
        "http://localhost:5010,http://127.0.0.1:5010",
    )

    app.config.from_mapping(
        SECRET_KEY=os.environ.get("AUTHLAB_SECRET_KEY", "dev-only-change-me"),
        DB_PATH=os.environ.get("AUTHLAB_DB", default_db),
        RP_ID=os.environ.get("AUTHLAB_RP_ID", "localhost"),
        RP_NAME=os.environ.get("AUTHLAB_RP_NAME", "AuthLab"),
        ORIGINS=[o.strip() for o in origins.split(",") if o.strip()],
        LAB_MODE=os.environ.get("AUTHLAB_LAB", "0") == "1",
        LAB_TOKEN=os.environ.get("AUTHLAB_LAB_TOKEN", "lab-dev-token"),
        SESSION_TTL=int(os.environ.get("AUTHLAB_SESSION_TTL", 60 * 60 * 8)),
        FLOW_TTL=int(os.environ.get("AUTHLAB_FLOW_TTL", 300)),
        TOTP_STEP=int(os.environ.get("AUTHLAB_TOTP_STEP", 30)),
        TOTP_DIGITS=int(os.environ.get("AUTHLAB_TOTP_DIGITS", 6)),
        TOTP_WINDOW=int(os.environ.get("AUTHLAB_TOTP_WINDOW", 1)),
        TOTP_REPLAY_PROTECTION=os.environ.get("AUTHLAB_TOTP_REPLAY_PROTECTION", "1") == "1",
        COUNTER_POLICY=os.environ.get("AUTHLAB_COUNTER_POLICY", "strict"),
        SHOW_RECOVERY_LINK=os.environ.get("AUTHLAB_SHOW_RECOVERY_LINK", "1") == "1",
        MAX_LOGIN_ATTEMPTS=int(os.environ.get("AUTHLAB_MAX_LOGIN_ATTEMPTS", 10)),
        LOGIN_WINDOW=int(os.environ.get("AUTHLAB_LOGIN_WINDOW", 900)),
        RECOVERY_TOKEN_TTL=int(os.environ.get("AUTHLAB_RECOVERY_TTL", 900)),
        RECOVERY_CODE_COUNT=int(os.environ.get("AUTHLAB_RECOVERY_CODES", 10)),
    )

    if test_config:
        app.config.update(test_config)

    db_dir = os.path.dirname(os.path.abspath(app.config["DB_PATH"]))
    os.makedirs(db_dir, exist_ok=True)
    init_db(app.config["DB_PATH"])
    app.teardown_appcontext(close_db)

    from .routes.auth import bp as auth_bp
    from .routes.lab import bp as lab_bp
    from .routes.pages import bp as pages_bp
    from .routes.passkeys import bp as passkeys_bp
    from .routes.recovery import bp as recovery_bp

    app.register_blueprint(pages_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(passkeys_bp)
    app.register_blueprint(recovery_bp)
    app.register_blueprint(lab_bp)

    @app.context_processor
    def inject_user():
        context = {"current_user": current_user(), "t": t}
        context.update(locale_context())
        return context

    app.add_template_filter(translate_message, "tr")
    app.add_template_filter(method_label, "method_label")
    app.add_template_filter(event_label, "event_label")

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'",
        )
        return response

    @app.errorhandler(400)
    def bad_request(err):
        if _wants_json():
            return jsonify(ok=False, error="bad_request", detail=str(err)), 400
        return "Bad request", 400

    @app.errorhandler(401)
    def unauthorized(err):
        if _wants_json():
            return jsonify(ok=False, error="unauthorized"), 401
        return "Unauthorized", 401

    @app.errorhandler(404)
    def not_found(err):
        if _wants_json():
            return jsonify(ok=False, error="not_found"), 404
        return "Not found", 404

    return app


def _wants_json() -> bool:
    return (
        request.path.startswith("/webauthn")
        or request.path.startswith("/lab")
        or request.path.startswith("/api")
        or request.is_json
        or request.accept_mimetypes.best == "application/json"
    )


app = create_app  # convenience for `flask --app authlab run`
