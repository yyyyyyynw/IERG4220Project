"""Browser + virtual-authenticator harness.

Chrome DevTools Protocol (CDP) virtual authenticators let the experiments run
without physical keys while still producing real WebAuthn ceremonies:

* ``transport=internal``  -> platform authenticator (synced-passkey model)
* ``transport=usb``       -> roaming authenticator (hardware-key model)

The harness starts two servers on loopback: the real AuthLab RP at
``app.lvh.me:5010`` and the hostile proxy at ``evil.app.lvh.me:5011``.  Both
names resolve to 127.0.0.1 through public wildcard DNS (lvh.me).
"""
from __future__ import annotations

import base64
import logging
import os
import secrets
import shutil
import sqlite3
import tempfile
import threading
import time
from contextlib import contextmanager

import requests
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from authlab import create_app
from authlab.security import totp_at

from .phishing_server import create_phishing_app

APP_HOST = "app.lvh.me"
PHISH_HOST = "evil.app.lvh.me"
APP_PORT = 5010
PHISH_PORT = 5011
BASE = f"http://{APP_HOST}:{APP_PORT}"
PHISH_BASE = f"http://{PHISH_HOST}:{PHISH_PORT}"
DEFAULT_PASSWORD = "correct horse battery staple"
SECURE_ORIGINS = f"http://{APP_HOST}:{APP_PORT},http://{PHISH_HOST}:{PHISH_PORT}"

logging.getLogger("werkzeug").setLevel(logging.ERROR)


class _Server:
    def __init__(self, app, port: int):
        self.app = app
        self.port = port
        self.httpd = None
        self.thread = None

    def start(self):
        self.httpd = make_server("127.0.0.1", self.port, self.app, threaded=True)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread is not None:
            self.thread.join(timeout=3)


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_to_std(text: str) -> str:
    raw = base64.urlsafe_b64decode(text + "=" * ((4 - len(text) % 4) % 4))
    return base64.b64encode(raw).decode("ascii")


class Lab:
    """Owns the servers, browser, and database for one experiment run."""

    def __init__(self, headless: bool = True, counter_policy: str = "strict"):
        self.tmpdir = tempfile.mkdtemp(prefix="authlab_exp_")
        self.db_path = os.path.join(self.tmpdir, "authlab.sqlite3")
        self.lab_token = secrets.token_urlsafe(24)
        self.counter_policy = counter_policy
        self._user_seq = 0

        self.app = create_app({
            "DB_PATH": self.db_path,
            "SECRET_KEY": secrets.token_hex(32),
            "RP_ID": APP_HOST,
            "ORIGINS": [BASE],
            "LAB_MODE": True,
            "LAB_TOKEN": self.lab_token,
            "SHOW_RECOVERY_LINK": True,
            "COUNTER_POLICY": counter_policy,
            "TOTP_REPLAY_PROTECTION": True,
            "SESSION_TTL": 60 * 60,
            "FLOW_TTL": 300,
        })
        self.app_server = _Server(self.app, APP_PORT)
        self.phish_app = create_phishing_app(BASE, self.lab_token)
        self.phish_server = _Server(self.phish_app, PHISH_PORT)
        self.playwright = None
        self.browser = None
        self.http = requests.Session()
        self.http.trust_env = False
        self._started = False

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self):
        self.app_server.start()
        self.phish_server.start()
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(
            channel="chrome",
            headless=True,
            args=[
                "--no-proxy-server",
                f"--unsafely-treat-insecure-origin-as-secure={SECURE_ORIGINS}",
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-default-apps",
                "--disable-sync",
            ],
        )
        self._started = True
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self.browser is not None:
                self.browser.close()
        finally:
            if self.playwright is not None:
                self.playwright.stop()
            self.phish_server.stop()
            self.app_server.stop()
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    # -- helpers -----------------------------------------------------------
    def next_username(self, prefix: str = "user") -> str:
        self._user_seq += 1
        return f"{prefix}{self._user_seq:03d}"

    def state(self, username: str) -> dict:
        response = self.http.get(
            BASE + "/lab/state", params={"username": username},
            headers={"X-AuthLab-Lab": self.lab_token}, timeout=10,
        )
        response.raise_for_status()
        return response.json()

    def db_rows(self, sql: str, params: tuple = ()) -> list[dict]:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            return [dict(row) for row in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()

    def db_execute(self, sql: str, params: tuple = ()) -> None:
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

    def totp_for(self, username: str, offset_steps: int = 0) -> str:
        state = self.state(username)
        at = time.time() + offset_steps * 30
        return totp_at(state["totp_secret"], at)[0]

    def mark_synced(self, credential_id: str) -> dict:
        response = self.http.post(
            BASE + "/lab/credentials/mark-synced",
            json={"credential_id": credential_id},
            headers={"X-AuthLab-Lab": self.lab_token}, timeout=10,
        )
        return response.json()

    def client(self) -> "Client":
        return Client(self)

    def restart_flask(self, **overrides):
        """Restart the RP with different config (e.g. naive TOTP policy)."""
        self.app_server.stop()
        cfg = {
            "DB_PATH": self.db_path,
            "SECRET_KEY": self.app.config["SECRET_KEY"],
            "RP_ID": APP_HOST,
            "ORIGINS": [BASE],
            "LAB_MODE": True,
            "LAB_TOKEN": self.lab_token,
            "SHOW_RECOVERY_LINK": True,
            "COUNTER_POLICY": self.counter_policy,
            "TOTP_REPLAY_PROTECTION": True,
            "SESSION_TTL": 60 * 60,
            "FLOW_TTL": 300,
        }
        cfg.update(overrides)
        self.app = create_app(cfg)
        self.app_server = _Server(self.app, APP_PORT)
        self.app_server.start()


class Client:
    """A fresh browser context with its own virtual authenticators."""

    def __init__(self, lab: Lab):
        self.lab = lab
        self.context = None
        self.page = None
        self.cdp = None
        self.authenticators: dict[str, str] = {}

    def __enter__(self):
        self.context = self.lab.browser.new_context()
        self.context.add_init_script("window.__AUTH_LAB_TIMEOUT_MS = 5000;")
        self.page = self.context.new_page()
        self.cdp = self.context.new_cdp_session(self.page)
        self.cdp.send("WebAuthn.enable")
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.context is not None:
            self.context.close()

    # -- authenticators ----------------------------------------------------
    def add_authenticator(self, kind: str = "passkey") -> str:
        transport = "internal" if kind == "passkey" else "usb"
        result = self.cdp.send("WebAuthn.addVirtualAuthenticator", {
            "options": {
                "protocol": "ctap2",
                "transport": transport,
                "hasResidentKey": True,
                "hasUserVerification": True,
                "isUserVerified": True,
                "automaticPresenceSimulation": True,
                "ctap2Version": "ctap2_1",
            }
        })
        auth_id = result["authenticatorId"]
        self.authenticators[kind] = auth_id
        return auth_id

    def remove_authenticator(self, auth_id: str) -> None:
        self.cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": auth_id})

    def set_presence(self, auth_id: str, enabled: bool) -> None:
        self.cdp.send("WebAuthn.setAutomaticPresenceSimulation", {
            "authenticatorId": auth_id, "enabled": enabled,
        })

    def cdp_credentials(self, auth_id: str) -> list[dict]:
        result = self.cdp.send("WebAuthn.getCredentials", {"authenticatorId": auth_id})
        return result.get("credentials", [])

    def export_credential(self, auth_id: str, index: int = 0) -> dict:
        credentials = self.cdp_credentials(auth_id)
        if not credentials:
            raise RuntimeError("no credential on virtual authenticator")
        credential = dict(credentials[index])
        credential["_credential_id_b64url"] = b64u(
            base64.b64decode(credential["credentialId"])
        )
        return credential

    def add_credential(self, auth_id: str, credential: dict, *,
                       backup_eligible: bool | None = None,
                       backup_state: bool | None = None,
                       sign_count: int | None = None) -> None:
        payload = {k: v for k, v in credential.items() if not k.startswith("_")}
        if backup_eligible is not None:
            payload["backupEligibility"] = backup_eligible
        if backup_state is not None:
            payload["backupState"] = backup_state
        if sign_count is not None:
            payload["signCount"] = sign_count
        self.cdp.send("WebAuthn.addCredential", {
            "authenticatorId": auth_id, "credential": payload,
        })

    def clear_credentials(self, auth_id: str) -> None:
        self.cdp.send("WebAuthn.clearCredentials", {"authenticatorId": auth_id})

    # -- UI flows ----------------------------------------------------------
    def register(self, username: str, password: str = DEFAULT_PASSWORD) -> dict:
        self.page.goto(BASE + "/register", wait_until="load")
        self.page.fill("#username", username)
        self.page.fill("#password", password)
        self.page.fill("#confirm", password)
        t0 = time.perf_counter()
        self.page.click("#register-submit")
        self.page.wait_for_url("**/enroll", timeout=15000)
        elapsed = (time.perf_counter() - t0) * 1000
        secret = self.page.locator("#totp-secret").inner_text().strip()
        codes = self.page.locator("#recovery-codes code").all_text_contents()
        return {
            "username": username, "password": password,
            "totp_secret": secret, "recovery_codes": codes,
            "elapsed_ms": elapsed,
        }

    def enroll(self, kind: str = "passkey") -> dict:
        self.page.goto(BASE + "/enroll", wait_until="load")
        selector = "#enroll-passkey" if kind == "passkey" else "#enroll-hardware"
        t0 = time.perf_counter()
        self.page.click(selector)
        self.page.wait_for_selector("#enroll-status.ok", timeout=20000)
        status = self.page.locator("#enroll-status").inner_text()
        timing = self.page.evaluate("() => window.AuthLab.getTiming()")
        self.page.wait_for_timeout(900)  # let the page reload
        return {
            "ok": True, "kind": kind, "status": status,
            "elapsed_ms": (time.perf_counter() - t0) * 1000,
            "client_timing": timing,
        }

    def clear_cookies(self) -> None:
        self.context.clear_cookies()

    def login_password(self, username: str, password: str,
                       code: str | None = None,
                       wait_after: bool = True,
                       timeout: int = 8000) -> dict:
        self.page.goto(BASE + "/login", wait_until="load")
        self.page.fill("#login-username", username)
        self.page.fill("#login-password", password)
        t0 = time.perf_counter()
        self.page.click("#login-password-submit")
        self.page.wait_for_load_state("load")
        stage = "password"
        if "/login/totp" in self.page.url:
            stage = "totp"
            if code is None:
                code = self.lab.totp_for(username)
            self.page.fill("#totp-code", code)
            self.page.click("#totp-submit")
            try:
                self.page.wait_for_url("**/dashboard", timeout=timeout)
                ok = True
            except Exception:
                ok = False
        else:
            ok = "/dashboard" in self.page.url
        elapsed = (time.perf_counter() - t0) * 1000
        status = ""
        if not ok and self.page.locator(".flash.error").count():
            status = self.page.locator(".flash.error").first.inner_text()
        return {
            "ok": ok, "stage": stage, "elapsed_ms": elapsed,
            "status": status, "url": self.page.url,
            "client_timing": self.page.evaluate(
                "() => window.AuthLab ? window.AuthLab.getTiming() : null"
            ) if wait_after else None,
        }

    def login_webauthn(self, kind: str = "passkey",
                       username: str | None = None,
                       timeout: int = 15000) -> dict:
        self.page.goto(BASE + "/login", wait_until="load")
        if kind == "passkey":
            self.page.click('.tab[data-tab="passkey"]')
            button = "#login-passkey"
        else:
            self.page.click('.tab[data-tab="hardware"]')
            if username:
                self.page.fill("#hardware-username", username)
            button = "#login-hardware"
        captured: dict = {}

        def _capture(request):
            if (request.method == "POST"
                    and request.url.endswith("/webauthn/login/verify")):
                try:
                    captured["payload"] = request.post_data_json
                except Exception:
                    pass

        self.page.on("request", _capture)
        t0 = time.perf_counter()
        try:
            self.page.click(button)
            try:
                self.page.wait_for_url("**/dashboard", timeout=timeout)
                ok = True
            except Exception:
                ok = False
        finally:
            self.page.remove_listener("request", _capture)
        elapsed = (time.perf_counter() - t0) * 1000
        status = ""
        if self.page.locator("#auth-status").count():
            status = self.page.locator("#auth-status").inner_text()
        return {
            "ok": ok, "kind": kind, "elapsed_ms": elapsed,
            "status": status, "url": self.page.url,
            "assertion_payload": captured.get("payload"),
            "client_timing": self.page.evaluate(
                "() => window.AuthLab ? window.AuthLab.getTiming() : null"
            ),
        }

    def logout_ui(self) -> None:
        self.page.goto(BASE + "/dashboard", wait_until="load")
        self.page.evaluate(
            "document.querySelector('form[action=\"/logout\"]').submit()"
        )
        self.page.wait_for_url(BASE + "/", timeout=10000)

    # -- phishing ----------------------------------------------------------
    def phish_password(self, username: str, password: str,
                       code: str | None = None, policy: str = "strict") -> dict:
        self.page.goto(PHISH_BASE + "/?policy=" + policy, wait_until="load")
        self.page.fill("#phish-username", username)
        self.page.fill("#phish-password", password)
        if code is None:
            code = self.lab.totp_for(username)
        self.page.fill("#phish-totp", code)
        self.page.click("#phish-password-submit")
        self.page.wait_for_function("() => window.__phish", timeout=25000)
        return self.page.evaluate("() => window.__phish")

    def phish_webauthn(self, kind: str, policy: str = "strict",
                       username: str | None = None) -> dict:
        self.page.goto(PHISH_BASE + "/?policy=" + policy, wait_until="load")
        if username:
            self.page.fill("#phish-username", username)
        button = "#phish-passkey" if kind == "passkey" else "#phish-hardware"
        self.page.click(button)
        self.page.wait_for_function("() => window.__phish", timeout=25000)
        return self.page.evaluate("() => window.__phish")

    def phish_naive(self) -> dict:
        self.page.goto(PHISH_BASE + "/?policy=strict", wait_until="load")
        self.page.click("#phish-naive")
        self.page.wait_for_function("() => window.__phish", timeout=10000)
        return self.page.evaluate("() => window.__phish")

    def phish_password_direct(self, username: str, password: str,
                              code: str, delay: float = 0.0) -> dict:
        response = self.lab.http.post(
            PHISH_BASE + "/phish/password",
            json={"username": username, "password": password,
                  "totp": code, "delay": delay},
            timeout=30,
        )
        return response.json()

    # -- miscellaneous -----------------------------------------------------
    def navigate(self, path: str) -> None:
        self.page.goto(BASE + path, wait_until="load")

    def current_url(self) -> str:
        return self.page.url

    def body_text(self) -> str:
        return self.page.locator("body").inner_text()

    def cookies(self) -> list[dict]:
        return self.context.cookies()

    def set_cookies(self, cookies: list[dict]) -> None:
        self.context.clear_cookies()
        self.context.add_cookies(cookies)


@contextmanager
def new_lab(**kwargs):
    lab = Lab(**kwargs)
    try:
        with lab:
            yield lab
    finally:
        pass
