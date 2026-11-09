"""Run every controlled experiment and write machine-readable results.

Usage:
    python experiments/run_experiments.py
    python experiments/analyze.py

The suite uses Chrome + CDP virtual authenticators and two loopback servers,
so it needs no physical security key.  It takes a few minutes.
"""
from __future__ import annotations

import base64
import json
import os
import platform
import secrets
import sys
import time
import traceback
from datetime import datetime, timezone

# Allow both `python experiments/run_experiments.py` and
# `python -m experiments.run_experiments`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authlab.security import sha256_hex
from experiments.harness import BASE, DEFAULT_PASSWORD, Lab

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
TRIALS = 5
TRIALS_SMALL = 3
TRIALS_LATENCY = 10
NEW_PASSWORD = "new correct horse battery"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _env() -> dict:
    return {
        "date_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "rp_id": "app.lvh.me",
        "origin": BASE,
        "phishing_origin": "http://evil.app.lvh.me:5011",
        "server": "Flask development server (loopback)",
        "authenticator": "Chrome CDP virtual authenticator (CTAP2.1)",
    }


def _detail(success: bool, elapsed_ms=None, error=None, **extra) -> dict:
    return {
        "success": bool(success),
        "elapsed_ms": None if elapsed_ms is None else round(float(elapsed_ms), 3),
        "error": error,
        **extra,
    }


def summarize(scenario_id: str, category: str, name: str, method: str,
              outcome: str, success_meaning: str, trials: list[dict],
              expected: str = "") -> dict:
    n = len(trials)
    successes = sum(1 for t in trials if t.get("success"))
    durations = sorted(
        t["elapsed_ms"] for t in trials
        if t.get("elapsed_ms") is not None and t.get("success")
    )
    mean = sum(durations) / len(durations) if durations else None
    median = durations[len(durations) // 2] if durations else None
    return {
        "id": scenario_id,
        "category": category,
        "name": name,
        "method": method,
        "outcome": outcome,
        "success_meaning": success_meaning,
        "expected": expected,
        "trials": n,
        "successes": successes,
        "rate": (successes / n) if n else None,
        "mean_ms": round(mean, 3) if mean is not None else None,
        "median_ms": round(median, 3) if median is not None else None,
        "details": trials,
    }


def _client(lab: Lab, kind: str | None = None):
    client = lab.client()
    client.__enter__()
    if kind:
        client.add_authenticator(kind)
    return client


def _close(client):
    client.__exit__(None, None, None)


def _new_user(lab: Lab, kind: str | None, prefix: str):
    """Create a client, register a user, and optionally enrol a credential."""
    client = _client(lab, kind)
    username = lab.next_username(prefix)
    user = client.register(username)
    if kind:
        enroll = client.enroll(kind)
        user["enrollment"] = enroll
    return client, user


# ---------------------------------------------------------------------------
# Phishing
# ---------------------------------------------------------------------------

def scenario_p1_password_phishing(lab: Lab) -> dict:
    trials = []
    for _ in range(TRIALS):
        try:
            client, user = _new_user(lab, None, "p1")
            client.logout_ui()
            code = lab.totp_for(user["username"])
            result = client.phish_password(
                user["username"], user["password"], code, policy="strict"
            )
            trials.append(_detail(
                bool(result.get("ok")), result.get("elapsed_ms"),
                stage=result.get("stage"),
                final_url=result.get("final_url"),
                policy="strict",
            ))
            _close(client)
        except Exception as exc:
            trials.append(_detail(False, error=repr(exc)))
    return summarize(
        "P1", "phishing", "Real-time phishing relay: password + TOTP",
        "password_totp", "attack", "attacker logs in",
        trials, "success expected without origin binding",
    )


def scenario_p1b_password_replay(lab: Lab) -> dict:
    trials = []
    for _ in range(TRIALS):
        try:
            client, user = _new_user(lab, None, "p1r")
            client.logout_ui()
            code = lab.totp_for(user["username"])
            first = client.phish_password(
                user["username"], user["password"], code, policy="strict"
            )
            replay = client.phish_password_direct(
                user["username"], user["password"], code
            )
            trials.append(_detail(
                bool(replay.get("ok")),
                replay.get("elapsed_ms"),
                first_ok=bool(first.get("ok")),
                replay_url=replay.get("final_url"),
                error=None if not replay.get("ok") else "replay accepted",
            ))
            _close(client)
        except Exception as exc:
            trials.append(_detail(False, error=repr(exc)))
    return summarize(
        "P1b", "replay", "Replay a phished TOTP code in a fresh session",
        "password_totp", "attack", "replay accepted",
        trials, "blocked by monotonic TOTP counter",
    )


def scenario_p1c_expired_totp(lab: Lab) -> dict:
    trials = []
    for _ in range(TRIALS_SMALL):
        try:
            client, user = _new_user(lab, None, "p1e")
            client.logout_ui()
            old_code = lab.totp_for(user["username"], offset_steps=-2)
            result = client.phish_password_direct(
                user["username"], user["password"], old_code
            )
            trials.append(_detail(
                bool(result.get("ok")), result.get("elapsed_ms"),
                stage=result.get("stage"),
                final_url=result.get("final_url"),
            ))
            _close(client)
        except Exception as exc:
            trials.append(_detail(False, error=repr(exc)))
    return summarize(
        "P1c", "replay", "Expired TOTP code (outside ±1 step window)",
        "password_totp", "attack", "expired code accepted",
        trials, "blocked by the 30-second window",
    )


def scenario_p1d_naive_totp(lab: Lab) -> dict:
    """Counterfactual: the same code accepted twice when replay protection is off."""
    trials = []
    for _ in range(TRIALS):
        try:
            client, user = _new_user(lab, None, "p1n")
            code = lab.totp_for(user["username"])
            payload = {"username": user["username"], "code": code,
                       "enforce_replay": False, "update": False}
            first = lab.http.post(BASE + "/lab/totp/verify", headers={
                "X-AuthLab-Lab": lab.lab_token}, json=payload, timeout=10).json()
            second = lab.http.post(BASE + "/lab/totp/verify", headers={
                "X-AuthLab-Lab": lab.lab_token}, json=payload, timeout=10).json()
            trials.append(_detail(
                bool(first.get("ok") and second.get("ok")),
                first_ok=first.get("ok"), second_ok=second.get("ok"),
                policy="no-replay-protection",
            ))
            _close(client)
        except Exception as exc:
            trials.append(_detail(False, error=repr(exc)))
    return summarize(
        "P1d", "replay", "Naive TOTP verifier accepts the same code twice",
        "password_totp", "attack", "second use accepted",
        trials, "demonstrates the necessity of server-side replay state",
    )


def _phishing_webauthn_scenario(lab: Lab, scenario_id: str, name: str,
                                method: str, kind: str, policy: str,
                                naive: bool, trials_n: int,
                                expected: str) -> dict:
    trials = []
    for _ in range(trials_n):
        try:
            client, user = _new_user(lab, kind, scenario_id.lower())
            client.logout_ui()
            if naive:
                result = client.phish_naive()
            else:
                result = client.phish_webauthn(kind, policy=policy,
                                               username=user["username"])
            trials.append(_detail(
                bool(result.get("ok")),
                result.get("elapsed_ms"),
                error=result.get("error"),
                origin=result.get("origin"),
                policy=policy,
                verify_status=result.get("verify_status"),
            ))
            _close(client)
        except Exception as exc:
            trials.append(_detail(False, error=repr(exc)))
    return summarize(
        scenario_id, "phishing", name, method, "attack",
        "attacker logs in", trials, expected,
    )


def scenario_p2_passkey_naive(lab: Lab) -> dict:
    return _phishing_webauthn_scenario(
        lab, "P2", "Lookalike origin asks for its own RP ID",
        "synced_passkey", "passkey", "strict", True, TRIALS_SMALL,
        "no credential exists for the attacker RP ID",
    )


def scenario_p3_passkey_strict(lab: Lab) -> dict:
    return _phishing_webauthn_scenario(
        lab, "P3", "Relay through lookalike subdomain; RP checks origin",
        "synced_passkey", "passkey", "strict", False, TRIALS,
        "origin check rejects the assertion",
    )


def scenario_p4_passkey_permissive(lab: Lab) -> dict:
    return _phishing_webauthn_scenario(
        lab, "P4", "Same relay; RP skips origin check (misconfiguration)",
        "synced_passkey", "passkey", "permissive", False, TRIALS,
        "permissive verifier accepts the assertion",
    )


def scenario_p5_hardware_naive(lab: Lab) -> dict:
    return _phishing_webauthn_scenario(
        lab, "P5", "Lookalike origin asks for its own RP ID",
        "hardware_key", "hardware", "strict", True, TRIALS_SMALL,
        "no credential exists for the attacker RP ID",
    )


def scenario_p6_hardware_strict(lab: Lab) -> dict:
    return _phishing_webauthn_scenario(
        lab, "P6", "Relay through lookalike subdomain; RP checks origin",
        "hardware_key", "hardware", "strict", False, TRIALS,
        "origin check rejects the assertion",
    )


def scenario_p7_hardware_permissive(lab: Lab) -> dict:
    return _phishing_webauthn_scenario(
        lab, "P7", "Same relay; RP skips origin check (misconfiguration)",
        "hardware_key", "hardware", "permissive", False, TRIALS,
        "permissive verifier accepts the assertion",
    )


# ---------------------------------------------------------------------------
# Replay / counter experiments
# ---------------------------------------------------------------------------

def scenario_r1_totp_policy(lab: Lab) -> dict:
    trials = []
    for _ in range(TRIALS):
        try:
            client, user = _new_user(lab, None, "r1")
            code = lab.totp_for(user["username"])
            def verify(enforce, update=True):
                return lab.http.post(
                    BASE + "/lab/totp/verify",
                    headers={"X-AuthLab-Lab": lab.lab_token},
                    json={"username": user["username"], "code": code,
                          "enforce_replay": enforce, "update": update},
                    timeout=10,
                ).json()
            n1 = verify(False, update=False)
            n2 = verify(False, update=False)
            h1 = verify(True, update=True)
            h2 = verify(True, update=True)
            trials.append(_detail(
                bool(n1.get("ok") and n2.get("ok") and h1.get("ok")
                     and not h2.get("ok")),
                naive_first=n1.get("ok"), naive_second=n2.get("ok"),
                hardened_first=h1.get("ok"), hardened_second=h2.get("ok"),
            ))
            _close(client)
        except Exception as exc:
            trials.append(_detail(False, error=repr(exc)))
    return summarize(
        "R1", "replay", "TOTP: naive vs counter-enforcing verifier",
        "password_totp", "security", "naive accepts twice; hardened blocks",
        trials, "hardened verifier rejects the second use",
    )


def scenario_r2_totp_window(lab: Lab) -> dict:
    offsets = [-2, -1, 0, 1, 2]
    observations = {off: [] for off in offsets}
    for _ in range(TRIALS):
        try:
            client, user = _new_user(lab, None, "r2")
            for off in offsets:
                code = lab.totp_for(user["username"], offset_steps=off)
                result = lab.http.post(
                    BASE + "/lab/totp/verify",
                    headers={"X-AuthLab-Lab": lab.lab_token},
                    json={"username": user["username"], "code": code,
                          "enforce_replay": False, "update": False},
                    timeout=10,
                ).json()
                observations[off].append(bool(result.get("ok")))
            _close(client)
        except Exception as exc:
            for off in offsets:
                observations[off].append(False)
    details = []
    for off in offsets:
        values = observations[off]
        details.append({
            "success": any(values),
            "offset_steps": off,
            "accepted": sum(values),
            "trials": len(values),
            "rate": sum(values) / len(values) if values else 0,
        })
    return summarize(
        "R2", "replay", "TOTP acceptance by time-step offset",
        "password_totp", "security", "code accepted", details,
        "only -1, 0, +1 should be accepted",
    )


def _assertion_replay_scenario(lab: Lab, scenario_id: str, kind: str,
                               method: str, trials_n: int) -> dict:
    trials = []
    for _ in range(trials_n):
        try:
            client, user = _new_user(lab, kind, scenario_id.lower())
            client.logout_ui()
            login = client.login_webauthn(
                kind, username=user["username"], timeout=15000
            )
            payload = login.get("assertion_payload")
            if not payload:
                trials.append(_detail(False, error="no assertion captured",
                                      login_ok=login.get("ok")))
                _close(client)
                continue
            same = lab.http.post(
                BASE + "/webauthn/login/verify", json=payload, timeout=10
            )
            same_json = same.json()
            options = lab.http.post(
                BASE + "/webauthn/login/options",
                json={"kind": kind, "username": user["username"]}, timeout=10,
            ).json()
            replay_payload = dict(payload)
            replay_payload["flow_id"] = options["flow_id"]
            new = lab.http.post(
                BASE + "/webauthn/login/verify", json=replay_payload, timeout=10
            )
            new_json = new.json()
            trials.append(_detail(
                bool(not same_json.get("ok") and not new_json.get("ok")),
                same_status=same.status_code,
                same_error=same_json.get("error"),
                new_status=new.status_code,
                new_error=new_json.get("error"),
            ))
            _close(client)
        except Exception as exc:
            trials.append(_detail(False, error=repr(exc)))
    return summarize(
        scenario_id, "replay", "Replay a captured WebAuthn assertion",
        method, "security", "both replays blocked", trials,
        "same challenge and fresh challenge must both fail",
    )


def scenario_r3_passkey_replay(lab: Lab) -> dict:
    return _assertion_replay_scenario(
        lab, "R3", "passkey", "synced_passkey", TRIALS_SMALL
    )


def scenario_r4_hardware_replay(lab: Lab) -> dict:
    return _assertion_replay_scenario(
        lab, "R4", "hardware", "hardware_key", TRIALS_SMALL
    )


def scenario_r5_counter(lab: Lab) -> dict:
    trials = []
    for _ in range(TRIALS_SMALL):
        try:
            client, user = _new_user(lab, "hardware", "r5")
            auth_a = client.authenticators["hardware"]
            credential = client.export_credential(auth_a)
            original = int(credential.get("signCount", 1))
            client.remove_authenticator(auth_a)
            auth_b = client.add_authenticator("hardware")
            client.add_credential(
                auth_b, credential, backup_eligible=False,
                backup_state=False, sign_count=max(0, original - 1),
            )
            client.logout_ui()
            result = client.login_webauthn(
                "hardware", username=user["username"], timeout=8000
            )
            trials.append(_detail(
                bool(not result.get("ok")),
                result.get("elapsed_ms"),
                original_sign_count=original,
                clone_sign_count=max(0, original - 1),
                status=result.get("status"),
            ))
            _close(client)
        except Exception as exc:
            trials.append(_detail(False, error=repr(exc)))
    return summarize(
        "R5", "replay", "Hardware-key clone with a lagging signature counter",
        "hardware_key", "security", "lagging clone blocked", trials,
        "counter regression is detected",
    )


def scenario_r6_counter_ahead(lab: Lab) -> dict:
    trials = []
    for _ in range(TRIALS_SMALL):
        try:
            client, user = _new_user(lab, "hardware", "r6")
            auth_a = client.authenticators["hardware"]
            credential = client.export_credential(auth_a)
            original = int(credential.get("signCount", 1))
            client.remove_authenticator(auth_a)
            auth_b = client.add_authenticator("hardware")
            client.add_credential(
                auth_b, credential, backup_eligible=False,
                backup_state=False, sign_count=original + 10,
            )
            client.logout_ui()
            result = client.login_webauthn(
                "hardware", username=user["username"], timeout=8000
            )
            trials.append(_detail(
                bool(result.get("ok")),
                result.get("elapsed_ms"),
                original_sign_count=original,
                clone_sign_count=original + 10,
                status=result.get("status"),
            ))
            _close(client)
        except Exception as exc:
            trials.append(_detail(False, error=repr(exc)))
    return summarize(
        "R6", "replay", "Hardware-key clone with a forged high counter",
        "hardware_key", "attack", "clone accepted", trials,
        "counter checks only detect clones behind the stored value",
    )


def scenario_r7_synced_counter(lab: Lab) -> dict:
    trials = []
    for _ in range(TRIALS_SMALL):
        try:
            client, user = _new_user(lab, "passkey", "r7")
            auth_a = client.authenticators["passkey"]
            credential = client.export_credential(auth_a)
            cid = credential["_credential_id_b64url"]
            client.remove_authenticator(auth_a)
            auth_b = client.add_authenticator("passkey")
            client.add_credential(
                auth_b, credential, backup_eligible=True,
                backup_state=True, sign_count=0,
            )
            lab.mark_synced(cid)
            client.logout_ui()
            result = client.login_webauthn("passkey", timeout=8000)
            trials.append(_detail(
                bool(result.get("ok")),
                result.get("elapsed_ms"),
                backup_state=result.get("client_timing") is not None,
                status=result.get("status"),
            ))
            _close(client)
        except Exception as exc:
            trials.append(_detail(False, error=repr(exc)))
    return summarize(
        "R7", "replay", "Synced passkey with a zero/non-monotonic counter",
        "synced_passkey", "security", "synced credential accepted", trials,
        "synced passkeys cannot be held to a strict counter",
    )


# ---------------------------------------------------------------------------
# Sync, device loss, backup, and recovery
# ---------------------------------------------------------------------------

def scenario_s1_synced_restore(lab: Lab) -> dict:
    trials = []
    for _ in range(TRIALS):
        try:
            client, user = _new_user(lab, "passkey", "s1")
            auth_a = client.authenticators["passkey"]
            credential = client.export_credential(auth_a)
            cid = credential["_credential_id_b64url"]
            client.remove_authenticator(auth_a)
            auth_b = client.add_authenticator("passkey")
            client.add_credential(
                auth_b, credential, backup_eligible=True,
                backup_state=True, sign_count=0,
            )
            lab.mark_synced(cid)
            client.logout_ui()
            result = client.login_webauthn("passkey", timeout=8000)
            trials.append(_detail(
                bool(result.get("ok")), result.get("elapsed_ms"),
                status=result.get("status"),
            ))
            _close(client)
        except Exception as exc:
            trials.append(_detail(False, error=repr(exc)))
    return summarize(
        "S1", "recovery", "Lose device A; restore synced passkey on device B",
        "synced_passkey", "task", "login succeeds", trials,
        "sync/backup makes device loss survivable",
    )


def scenario_s2_platform_loss(lab: Lab) -> dict:
    trials = []
    for _ in range(TRIALS_SMALL):
        try:
            client, user = _new_user(lab, "passkey", "s2")
            client.remove_authenticator(client.authenticators["passkey"])
            client.logout_ui()
            result = client.login_webauthn("passkey", timeout=8000)
            trials.append(_detail(
                bool(not result.get("ok")), result.get("elapsed_ms"),
                status=result.get("status"),
            ))
            _close(client)
        except Exception as exc:
            trials.append(_detail(False, error=repr(exc)))
    return summarize(
        "S2", "recovery", "Lose a device-bound platform credential (no sync)",
        "synced_passkey", "security", "lockout observed", trials,
        "no credential remains; no self-service path without recovery",
    )


def scenario_s3_hardware_loss(lab: Lab) -> dict:
    trials = []
    for _ in range(TRIALS_SMALL):
        try:
            client, user = _new_user(lab, "hardware", "s3")
            client.remove_authenticator(client.authenticators["hardware"])
            client.logout_ui()
            result = client.login_webauthn(
                "hardware", username=user["username"], timeout=8000
            )
            trials.append(_detail(
                bool(not result.get("ok")), result.get("elapsed_ms"),
                status=result.get("status"),
            ))
            _close(client)
        except Exception as exc:
            trials.append(_detail(False, error=repr(exc)))
    return summarize(
        "S3", "recovery", "Lose the only hardware key (no backup)",
        "hardware_key", "security", "lockout observed", trials,
        "no credential remains",
    )


def scenario_s4_hardware_backup(lab: Lab) -> dict:
    trials = []
    for _ in range(TRIALS_SMALL):
        try:
            client, user = _new_user(lab, "hardware", "s4")
            auth_a = client.authenticators["hardware"]
            client.remove_authenticator(auth_a)
            # Enrol the backup key while the session is still valid.
            auth_b = client.add_authenticator("hardware")
            enroll = client.enroll("hardware")
            client.logout_ui()
            result = client.login_webauthn(
                "hardware", username=user["username"], timeout=8000
            )
            trials.append(_detail(
                bool(result.get("ok")), result.get("elapsed_ms"),
                backup_enrollment_ms=enroll.get("elapsed_ms"),
                status=result.get("status"),
            ))
            _close(client)
        except Exception as exc:
            trials.append(_detail(False, error=repr(exc)))
    return summarize(
        "S4", "recovery", "Lose key A; sign in with enrolled backup key B",
        "hardware_key", "task", "login succeeds", trials,
        "a second physical key is a viable backup",
    )


def scenario_s5_hardware_recovery_code(lab: Lab) -> dict:
    trials = []
    for _ in range(TRIALS_SMALL):
        try:
            client, user = _new_user(lab, "hardware", "s5")
            client.remove_authenticator(client.authenticators["hardware"])
            client.logout_ui()
            client.navigate("/recovery")
            client.page.fill("#recovery-code-username", user["username"])
            client.page.fill("#recovery-code", user["recovery_codes"][0])
            t0 = time.perf_counter()
            client.page.click("#recovery-code-submit")
            try:
                client.page.wait_for_url("**/dashboard", timeout=10000)
                ok = True
            except Exception:
                ok = False
            trials.append(_detail(
                ok, (time.perf_counter() - t0) * 1000,
                status=client.page.url,
            ))
            _close(client)
        except Exception as exc:
            trials.append(_detail(False, error=repr(exc)))
    return summarize(
        "S5", "recovery", "Lose hardware key; use a one-time recovery code",
        "hardware_key", "task", "login succeeds", trials,
        "recovery code is the last self-service path",
    )


def scenario_s6_recovery_code_reuse(lab: Lab) -> dict:
    trials = []
    for _ in range(TRIALS_SMALL):
        try:
            client, user = _new_user(lab, None, "s6")
            client.logout_ui()
            client.navigate("/recovery")
            client.page.fill("#recovery-code-username", user["username"])
            client.page.fill("#recovery-code", user["recovery_codes"][0])
            client.page.click("#recovery-code-submit")
            client.page.wait_for_url("**/dashboard", timeout=10000)
            client.logout_ui()
            client.navigate("/recovery")
            client.page.fill("#recovery-code-username", user["username"])
            client.page.fill("#recovery-code", user["recovery_codes"][0])
            client.page.click("#recovery-code-submit")
            client.page.wait_for_load_state("load")
            reused = "/dashboard" in client.page.url
            trials.append(_detail(
                bool(not reused), status=client.page.url,
                body=client.page.locator("body").inner_text()[:160],
            ))
            _close(client)
        except Exception as exc:
            trials.append(_detail(False, error=repr(exc)))
    return summarize(
        "S6", "recovery", "Reuse a recovery code",
        "all", "security", "second use blocked", trials,
        "single-use enforcement",
    )


def _request_reset(client, username: str) -> str:
    client.navigate("/recovery")
    client.page.fill("#recovery-username", username)
    client.page.click("#recovery-request-submit")
    client.page.wait_for_selector("#reset-link", timeout=10000)
    link = client.page.locator("#reset-link").get_attribute("href")
    return link.rsplit("/", 1)[-1]


def _reset_post(token: str, password: str = NEW_PASSWORD):
    import requests
    session = requests.Session()
    session.trust_env = False
    return session.post(
        BASE + f"/recovery/reset/{token}",
        data={"password": password, "confirm": password},
        allow_redirects=True, timeout=15,
    )


def scenario_s7_email_reset(lab: Lab) -> dict:
    trials = []
    for _ in range(TRIALS_SMALL):
        try:
            client, user = _new_user(lab, None, "s7")
            token = _request_reset(client, user["username"])
            first = _reset_post(token)
            replay = _reset_post(token)
            client.navigate("/dashboard")
            old_session_revoked = "/login" in client.page.url
            old_login = client.login_password(
                user["username"], user["password"], timeout=3000
            )
            new_code = lab.totp_for(user["username"])
            new_login = client.login_password(
                user["username"], NEW_PASSWORD, new_code, timeout=8000
            )
            ok = (
                first.status_code == 200
                and "Password reset" in first.text
                and replay.status_code == 400
                and old_session_revoked
                and not old_login.get("ok")
                and new_login.get("ok")
            )
            trials.append(_detail(
                ok, first.elapsed.total_seconds() * 1000 if first.elapsed else None,
                reset_status=first.status_code,
                replay_status=replay.status_code,
                old_session_revoked=old_session_revoked,
                old_password_ok=old_login.get("ok"),
                new_password_ok=new_login.get("ok"),
                token_length=len(token),
            ))
            _close(client)
        except Exception as exc:
            trials.append(_detail(False, error=repr(exc)))
    return summarize(
        "S7", "recovery", "Email reset: single use, session revocation, TOTP rotation",
        "all", "security", "all recovery invariants hold", trials,
        "token replay blocked; old sessions/passwords invalid",
    )


def scenario_s8_email_token_expiry(lab: Lab) -> dict:
    trials = []
    for _ in range(TRIALS_SMALL):
        try:
            client, user = _new_user(lab, None, "s8")
            token = _request_reset(client, user["username"])
            lab.db_execute(
                "UPDATE recovery_tokens SET expires_at = ? WHERE token_hash = ?",
                (time.time() - 5, sha256_hex(token)),
            )
            response = _reset_post(token)
            trials.append(_detail(
                bool(response.status_code == 400),
                status=response.status_code,
            ))
            _close(client)
        except Exception as exc:
            trials.append(_detail(False, error=repr(exc)))
    return summarize(
        "S8", "recovery", "Use an expired email reset token",
        "all", "security", "expired token rejected", trials,
        "15-minute expiry enforced",
    )


# ---------------------------------------------------------------------------
# Usability measurements
# ---------------------------------------------------------------------------

def scenario_u1_latency(lab: Lab) -> dict:
    data = {
        "registration": [],
        "password_totp_login": [],
        "passkey_enroll": [],
        "passkey_login": [],
        "hardware_enroll": [],
        "hardware_login": [],
        "recovery_email_request": [],
        "recovery_email_reset": [],
        "recovery_code_login": [],
    }

    for _ in range(TRIALS_LATENCY):
        # Password + TOTP
        try:
            client, user = _new_user(lab, None, "u1p")
            data["registration"].append(user["elapsed_ms"])
            client.logout_ui()
            code = lab.totp_for(user["username"])
            result = client.login_password(user["username"], user["password"], code)
            if result.get("ok"):
                data["password_totp_login"].append(result["elapsed_ms"])
            _close(client)
        except Exception:
            pass

        # Passkey
        try:
            client, user = _new_user(lab, "passkey", "u1k")
            data["passkey_enroll"].append(user["enrollment"]["elapsed_ms"])
            client.logout_ui()
            result = client.login_webauthn("passkey")
            if result.get("ok"):
                data["passkey_login"].append(result["elapsed_ms"])
            _close(client)
        except Exception:
            pass

        # Hardware key
        try:
            client, user = _new_user(lab, "hardware", "u1h")
            data["hardware_enroll"].append(user["enrollment"]["elapsed_ms"])
            client.logout_ui()
            result = client.login_webauthn(
                "hardware", username=user["username"]
            )
            if result.get("ok"):
                data["hardware_login"].append(result["elapsed_ms"])
            _close(client)
        except Exception:
            pass

    for _ in range(TRIALS_SMALL):
        # Email recovery
        try:
            client, user = _new_user(lab, None, "u1r")
            t0 = time.perf_counter()
            token = _request_reset(client, user["username"])
            data["recovery_email_request"].append(
                (time.perf_counter() - t0) * 1000
            )
            t0 = time.perf_counter()
            response = _reset_post(token)
            if response.status_code == 200:
                data["recovery_email_reset"].append(
                    (time.perf_counter() - t0) * 1000
                )
            _close(client)
        except Exception:
            pass

        # Recovery code
        try:
            client, user = _new_user(lab, None, "u1c")
            client.logout_ui()
            client.navigate("/recovery")
            client.page.fill("#recovery-code-username", user["username"])
            client.page.fill("#recovery-code", user["recovery_codes"][0])
            t0 = time.perf_counter()
            client.page.click("#recovery-code-submit")
            try:
                client.page.wait_for_url("**/dashboard", timeout=10000)
                data["recovery_code_login"].append(
                    (time.perf_counter() - t0) * 1000
                )
            except Exception:
                pass
            _close(client)
        except Exception:
            pass

    return {
        "id": "U1",
        "category": "usability",
        "name": "Instrumented ceremony latency",
        "samples": {k: [round(x, 3) for x in v] for k, v in data.items()},
        "n": {k: len(v) for k, v in data.items()},
    }


def scenario_u2_error_paths(lab: Lab) -> dict:
    trials = []

    def add(name, method, action):
        try:
            t0 = time.perf_counter()
            result = action()
            login_ok = bool(result.get("ok"))
            trials.append({
                "name": name, "method": method,
                "login_ok": login_ok,
                # Every probe here is supposed to fail closed.
                "success": not login_ok,
                "blocked": not login_ok,
                "elapsed_ms": round((time.perf_counter() - t0) * 1000, 3),
                "status": result.get("status", ""),
            })
        except Exception as exc:
            trials.append({"name": name, "method": method,
                           "success": False, "blocked": False, "error": repr(exc)})

    for _ in range(TRIALS_SMALL):
        def wrong_password():
            client, user = _new_user(lab, None, "u2p")
            client.logout_ui()
            result = client.login_password(
                user["username"], "definitely wrong", timeout=3000
            )
            _close(client)
            return result
        add("wrong password", "password_totp", wrong_password)

        def wrong_totp():
            client, user = _new_user(lab, None, "u2t")
            client.logout_ui()
            result = client.login_password(
                user["username"], user["password"], "000000", timeout=3000
            )
            _close(client)
            return result
        add("wrong TOTP", "password_totp", wrong_totp)

        def passkey_lost():
            client, user = _new_user(lab, "passkey", "u2k")
            client.remove_authenticator(client.authenticators["passkey"])
            client.logout_ui()
            result = client.login_webauthn("passkey", timeout=8000)
            _close(client)
            return result
        add("no passkey credential", "synced_passkey", passkey_lost)

        def hardware_lost():
            client, user = _new_user(lab, "hardware", "u2h")
            client.remove_authenticator(client.authenticators["hardware"])
            client.logout_ui()
            result = client.login_webauthn(
                "hardware", username=user["username"], timeout=8000
            )
            _close(client)
            return result
        add("no hardware credential", "hardware_key", hardware_lost)

    return {
        "id": "U2",
        "category": "usability",
        "name": "Error paths and lockout feedback",
        "trials": trials,
        "n": len(trials),
    }


# ---------------------------------------------------------------------------
# Protocol checks
# ---------------------------------------------------------------------------

def protocol_checks(lab: Lab) -> dict:
    checks: dict = {}
    client, user = _new_user(lab, None, "proto")
    try:
        cookies = client.cookies()
        session_cookie = next(
            (c for c in cookies if c["name"] == "authlab_session"), None
        )
        checks["session_cookie_httponly"] = bool(
            session_cookie and session_cookie.get("httpOnly")
        )
        checks["session_cookie_samesite"] = (
            session_cookie.get("sameSite") if session_cookie else None
        )
        checks["session_cookie_secure"] = bool(
            session_cookie and session_cookie.get("secure")
        )

        options = lab.http.post(
            BASE + "/webauthn/login/options",
            json={"kind": "passkey"}, timeout=10,
        ).json()["options"]
        challenge = options["challenge"]
        checks["challenge_b64url_length"] = len(challenge)
        checks["challenge_entropy_bytes"] = len(base64.urlsafe_b64decode(
            challenge + "=" * ((4 - len(challenge) % 4) % 4)
        ))

        token = _request_reset(client, user["username"])
        checks["recovery_token_length"] = len(token)
        rows = lab.db_rows(
            "SELECT token_hash FROM recovery_tokens ORDER BY id DESC LIMIT 1"
        )
        stored = rows[0]["token_hash"] if rows else ""
        checks["recovery_token_hashed_at_rest"] = (
            bool(stored) and stored != token and stored == sha256_hex(token)
        )
        checks["recovery_token_plaintext_absent"] = token not in stored
    finally:
        _close(client)
    return checks


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _write_results(results: dict) -> str:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    path = os.path.join(RESULTS_DIR, "results.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)
    return path


def main() -> int:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    started = time.time()
    results: dict = {
        "meta": {
            "project": "Beyond TOTP: phishing resistance and account recovery",
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "environment": _env(),
        },
        "scenarios": [],
        "latency": {},
        "error_paths": {},
        "protocol_checks": {},
    }

    print("[*] starting lab (Chrome + virtual authenticators)")
    with Lab() as lab:
        results["meta"]["environment"]["chrome"] = lab.browser.version
        results["meta"]["environment"]["counter_policy"] = lab.counter_policy

        scenarios = [
            ("P1  password phishing", scenario_p1_password_phishing),
            ("P1b TOTP replay", scenario_p1b_password_replay),
            ("P1c expired TOTP", scenario_p1c_expired_totp),
            ("P1d naive TOTP", scenario_p1d_naive_totp),
            ("P2  passkey naive phishing", scenario_p2_passkey_naive),
            ("P3  passkey strict relay", scenario_p3_passkey_strict),
            ("P4  passkey permissive relay", scenario_p4_passkey_permissive),
            ("P5  hardware naive phishing", scenario_p5_hardware_naive),
            ("P6  hardware strict relay", scenario_p6_hardware_strict),
            ("P7  hardware permissive relay", scenario_p7_hardware_permissive),
            ("R1  TOTP policy", scenario_r1_totp_policy),
            ("R2  TOTP window", scenario_r2_totp_window),
            ("R3  passkey assertion replay", scenario_r3_passkey_replay),
            ("R4  hardware assertion replay", scenario_r4_hardware_replay),
            ("R5  counter regression", scenario_r5_counter),
            ("R6  counter ahead", scenario_r6_counter_ahead),
            ("R7  synced counter", scenario_r7_synced_counter),
            ("S1  synced restore", scenario_s1_synced_restore),
            ("S2  platform loss", scenario_s2_platform_loss),
            ("S3  hardware loss", scenario_s3_hardware_loss),
            ("S4  hardware backup", scenario_s4_hardware_backup),
            ("S5  hardware recovery code", scenario_s5_hardware_recovery_code),
            ("S6  recovery code reuse", scenario_s6_recovery_code_reuse),
            ("S7  email reset", scenario_s7_email_reset),
            ("S8  token expiry", scenario_s8_email_token_expiry),
        ]

        for label, fn in scenarios:
            print(f"[*] {label}")
            try:
                result = fn(lab)
            except Exception:
                traceback.print_exc()
                result = {
                    "id": label.split()[0], "name": label,
                    "error": traceback.format_exc(),
                    "trials": 0, "successes": 0, "rate": None,
                    "details": [],
                }
            results["scenarios"].append(result)
            print(
                f"    {result.get('successes')}/{result.get('trials')} "
                f"({result.get('rate')})"
            )
            _write_results(results)

        print("[*] U1 latency")
        results["latency"] = scenario_u1_latency(lab)
        print("    ", results["latency"]["n"])
        _write_results(results)

        print("[*] U2 error paths")
        results["error_paths"] = scenario_u2_error_paths(lab)
        print("    ", results["error_paths"]["n"])
        _write_results(results)

        print("[*] protocol checks")
        results["protocol_checks"] = protocol_checks(lab)
        _write_results(results)

    results["meta"]["duration_seconds"] = round(time.time() - started, 2)
    path = _write_results(results)
    print(f"[+] wrote {path}")
    print(f"[+] duration {results['meta']['duration_seconds']} s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
