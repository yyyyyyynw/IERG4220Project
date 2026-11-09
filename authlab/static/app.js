/* AuthLab browser helpers: WebAuthn JSON conversion + experiment timing. */
(function () {
  "use strict";

  function b64uEncode(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function b64uDecode(text) {
    const pad = text.length % 4 === 0 ? "" : "=".repeat(4 - (text.length % 4));
    const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/") + pad);
    return Uint8Array.from(binary, function (c) { return c.charCodeAt(0); });
  }

  async function postJSON(url, body) {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(body || {}),
    });
    let data = null;
    try { data = await response.json(); } catch (_) { data = { ok: false, error: "bad_response" }; }
    if (!response.ok || data.ok === false) {
      const error = new Error(data.error || ("http_" + response.status));
      error.data = data;
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function prepareCreationOptions(options) {
    const pk = Object.assign({}, options);
    pk.challenge = b64uDecode(pk.challenge);
    pk.user = Object.assign({}, pk.user, { id: b64uDecode(pk.user.id) });
    pk.excludeCredentials = (pk.excludeCredentials || []).map(function (c) {
      return Object.assign({}, c, { id: b64uDecode(c.id) });
    });
    return pk;
  }

  function prepareRequestOptions(options) {
    const pk = Object.assign({}, options);
    pk.challenge = b64uDecode(pk.challenge);
    pk.allowCredentials = (pk.allowCredentials || []).map(function (c) {
      return Object.assign({}, c, { id: b64uDecode(c.id) });
    });
    return pk;
  }

  function serializeRegistration(credential) {
    const response = {
      clientDataJSON: b64uEncode(credential.response.clientDataJSON),
      attestationObject: b64uEncode(credential.response.attestationObject),
      transports: [],
    };
    try {
      if (credential.response.getTransports) response.transports = credential.response.getTransports();
    } catch (_) {}
    return {
      id: credential.id,
      rawId: b64uEncode(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment,
      response: response,
    };
  }

  function serializeAssertion(credential) {
    const response = {
      clientDataJSON: b64uEncode(credential.response.clientDataJSON),
      authenticatorData: b64uEncode(credential.response.authenticatorData),
      signature: b64uEncode(credential.response.signature),
      userHandle: credential.response.userHandle
        ? b64uEncode(credential.response.userHandle) : null,
    };
    return {
      id: credential.id,
      rawId: b64uEncode(credential.rawId),
      type: credential.type,
      response: response,
    };
  }

  function statusElement() {
    return document.getElementById("enroll-status") ||
           document.getElementById("auth-status") ||
           document.getElementById("phish-status");
  }

  function setStatus(text, kind) {
    const el = statusElement();
    if (!el) return;
    el.textContent = text;
    el.className = "status" + (kind ? " " + kind : "");
  }

  function rememberTiming(timing) {
    try { sessionStorage.setItem("authlab.lastTiming", JSON.stringify(timing)); } catch (_) {}
  }

  function describeError(error) {
    if (!error) return "Unknown error";
    if (error.name === "NotAllowedError") return "Cancelled or no matching credential.";
    if (error.name === "SecurityError") return "Security error: origin/RP ID mismatch.";
    if (error.name === "InvalidStateError") return "This authenticator is already registered.";
    return error.name ? (error.name + ": " + error.message) : error.message;
  }

  const AuthLab = {
    b64uEncode: b64uEncode,
    b64uDecode: b64uDecode,
    postJSON: postJSON,
    lastTiming: null,

    async enroll(kind) {
      const start = performance.now();
      this.lastTiming = { action: "enroll", kind: kind, start: start, ok: false };
      try {
        setStatus("Waiting for authenticator…");
        const optionResponse = await postJSON("/webauthn/register/options", { kind: kind });
        const credential = await navigator.credentials.create({
          publicKey: prepareCreationOptions(optionResponse.options),
        });
        const result = await postJSON("/webauthn/register/verify", {
          flow_id: optionResponse.flow_id,
          kind: kind,
          credential: serializeRegistration(credential),
        });
        this.lastTiming.ok = true;
        this.lastTiming.end = performance.now();
        this.lastTiming.duration_ms = this.lastTiming.end - start;
        rememberTiming(this.lastTiming);
        setStatus("Enrolled: " + result.credential.label, "ok");
        window.setTimeout(function () { window.location.reload(); }, 700);
        return result;
      } catch (error) {
        this.lastTiming.end = performance.now();
        this.lastTiming.duration_ms = this.lastTiming.end - start;
        this.lastTiming.error = describeError(error);
        setStatus(describeError(error), "bad");
        throw error;
      }
    },

    async loginWebAuthn(kind) {
      const start = performance.now();
      this.lastTiming = { action: "login", kind: kind, start: start, ok: false };
      try {
        setStatus("Waiting for authenticator…");
        const usernameEl = document.getElementById("hardware-username");
        const username = kind === "hardware" && usernameEl ? usernameEl.value.trim() : null;
        const optionResponse = await postJSON("/webauthn/login/options", {
          kind: kind,
          username: username || null,
        });
        const publicKey = prepareRequestOptions(optionResponse.options);
        // The harness shortens the timeout so a "no authenticator" negative
        // test does not wait the full 60 seconds.
        if (window.__AUTH_LAB_TIMEOUT_MS) publicKey.timeout = window.__AUTH_LAB_TIMEOUT_MS;
        const credential = await navigator.credentials.get({ publicKey: publicKey });
        const result = await postJSON("/webauthn/login/verify", {
          flow_id: optionResponse.flow_id,
          credential: serializeAssertion(credential),
        });
        this.lastTiming.ok = true;
        this.lastTiming.end = performance.now();
        this.lastTiming.duration_ms = this.lastTiming.end - start;
        this.lastTiming.method = result.method;
        rememberTiming(this.lastTiming);
        setStatus("Signed in as " + result.username, "ok");
        window.location.href = result.redirect || "/dashboard";
        return result;
      } catch (error) {
        this.lastTiming.end = performance.now();
        this.lastTiming.duration_ms = this.lastTiming.end - start;
        this.lastTiming.error = describeError(error);
        setStatus(describeError(error), "bad");
        throw error;
      }
    },

    getTiming() {
      try {
        const raw = sessionStorage.getItem("authlab.lastTiming");
        if (raw) return JSON.parse(raw);
      } catch (_) {}
      return this.lastTiming;
    },

    async state() {
      const response = await fetch("/api/me", { credentials: "same-origin" });
      return response.json();
    },
  };

  window.AuthLab = AuthLab;
})();
