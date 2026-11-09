from __future__ import annotations

import json

from flask import Blueprint, abort, current_app, jsonify, request
from webauthn.helpers import bytes_to_base64url

from ..db import execute, query_all, query_one
from ..security import (
    constant_time, consume_flow, create_session, current_user, json_body,
    log_event, now, require_login, set_session_cookie, store_flow,
)
from ..webauthn_service import (
    authentication_options, check_authentication, check_registration,
    client_origin, counter_allows, credential_id_of, registration_options,
    user_handle_b64,
)

bp = Blueprint("passkeys", __name__)

FLOW_KIND_TO_DB = {"passkey": "platform", "hardware": "roaming"}
DB_KIND_TO_FLOW = {"platform": "passkey", "roaming": "hardware"}


def _full_user(user_id: int):
    return query_one("SELECT * FROM users WHERE id = ?", (user_id,))


def _device_type(verified) -> str:
    return str(getattr(verified.credential_device_type, "value",
                       verified.credential_device_type))


def _geo(user_id: int):
    return query_all(
        "SELECT * FROM credentials WHERE user_id = ? ORDER BY created_at", (user_id,)
    )


@bp.post("/webauthn/register/options")
@require_login
def register_options():
    data = json_body()
    kind = data.get("kind")
    if kind not in FLOW_KIND_TO_DB:
        return jsonify(ok=False, error="invalid_kind"), 400

    user = _full_user(current_user()["user_id"])
    existing = query_all(
        "SELECT credential_id FROM credentials WHERE user_id = ? AND kind = ?",
        (user["id"], FLOW_KIND_TO_DB[kind]),
    )
    options = registration_options(user, kind, [r["credential_id"] for r in existing])
    flow_id = store_flow(
        user["id"], "register", kind, options["challenge"],
        current_app.config["RP_ID"], request.headers.get("Origin"),
    )
    return jsonify(ok=True, flow_id=flow_id, options=options)


@bp.post("/webauthn/register/verify")
@require_login
def register_verify():
    data = json_body()
    flow = consume_flow(data.get("flow_id"), "register")
    credential = data.get("credential")
    if flow is None or not isinstance(credential, dict):
        return jsonify(ok=False, error="invalid_flow"), 400
    if flow["user_id"] != current_user()["user_id"]:
        return jsonify(ok=False, error="wrong_user"), 403
    kind = data.get("kind")
    if kind != flow["kind"] or kind not in FLOW_KIND_TO_DB:
        return jsonify(ok=False, error="kind_mismatch"), 400

    try:
        verified = check_registration(credential, flow["challenge"])
    except Exception as exc:  # py_webauthn raises several specific types
        log_event("webauthn_register", user_id=flow["user_id"],
                  username=current_user()["username"], method=kind,
                  success=False, detail=f"verify: {exc}")
        return jsonify(ok=False, error="registration_verification_failed"), 401

    cid = bytes_to_base64url(verified.credential_id)
    if query_one("SELECT id FROM credentials WHERE credential_id = ?", (cid,)):
        return jsonify(ok=False, error="credential_already_registered"), 409

    device_type = _device_type(verified)
    backup_eligible = device_type == "multi_device"
    backup_state = bool(verified.credential_backed_up)

    # A hardware security key must be a single-device, non-exportable
    # authenticator.  A backup-eligible credential on a roaming authenticator
    # is a different (and weaker) object.
    if kind == "hardware" and (backup_eligible or backup_state):
        log_event("webauthn_register", user_id=flow["user_id"],
                  username=current_user()["username"], method=kind,
                  success=False, detail="hardware credential is backup eligible")
        return jsonify(ok=False, error="hardware_must_be_device_bound"), 400

    transports = (credential.get("response") or {}).get("transports") or []
    label = (
        "Synced passkey" if kind == "passkey" and backup_eligible
        else "Platform passkey (device-bound)" if kind == "passkey"
        else "Hardware security key"
    )

    execute(
        "INSERT INTO credentials(user_id, credential_id, public_key, sign_count,"
        " transports, aaguid, kind, backup_eligible, backup_state, label,"
        " created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            flow["user_id"], cid, verified.credential_public_key,
            verified.sign_count, json.dumps(transports), str(verified.aaguid),
            FLOW_KIND_TO_DB[kind], int(backup_eligible), int(backup_state),
            label, now(),
        ),
    )
    log_event("webauthn_register", user_id=flow["user_id"],
              username=current_user()["username"], method=kind, success=True,
              detail=f"{label}; device_type={device_type}; bs={backup_state}")
    return jsonify(
        ok=True,
        credential={
            "credential_id": cid,
            "kind": FLOW_KIND_TO_DB[kind],
            "label": label,
            "device_type": device_type,
            "backup_eligible": backup_eligible,
            "backup_state": backup_state,
            "sign_count": verified.sign_count,
        },
    )


@bp.post("/webauthn/login/options")
def login_options():
    data = json_body()
    kind = data.get("kind", "passkey")
    username = (data.get("username") or "").strip() or None
    if kind not in FLOW_KIND_TO_DB:
        return jsonify(ok=False, error="invalid_kind"), 400

    user = None
    credentials = []
    if username:
        user = query_one("SELECT * FROM users WHERE username = ?", (username,))
    if user is not None:
        credentials = query_all(
            "SELECT * FROM credentials WHERE user_id = ? AND kind = ?",
            (user["id"], FLOW_KIND_TO_DB[kind]),
        )

    options = authentication_options(kind, credentials)
    flow_id = store_flow(
        user["id"] if user else None, "authenticate", kind,
        options["challenge"], current_app.config["RP_ID"],
        request.headers.get("Origin"),
    )
    # The response shape is deliberately identical for known and unknown
    # usernames (account-enumeration resistance).
    return jsonify(ok=True, flow_id=flow_id, options=options)


def _finish_authentication(flow, credential: dict,
                           origins: list[str] | None = None,
                           counter_policy: str | None = None):
    """Verify an assertion and return ``(user, details, error)``.

    ``error`` is a ``(reason, http_status)`` tuple.  All cryptographic checks
    (challenge, RP ID, origin, UV, signature) are delegated to py_webauthn;
    the counter policy and account binding are explicit here.
    """
    if not isinstance(credential, dict):
        return None, None, ("missing_credential", 400)

    cid = credential_id_of(credential)
    cred = query_one("SELECT * FROM credentials WHERE credential_id = ?", (cid,))
    if cred is None:
        return None, None, ("unknown_credential", 401)

    flow_kind = flow["kind"]
    if flow_kind and flow_kind != DB_KIND_TO_FLOW[cred["kind"]]:
        return None, None, ("method_mismatch", 401)
    if flow["user_id"] is not None and flow["user_id"] != cred["user_id"]:
        return None, None, ("account_mismatch", 401)

    user = _full_user(cred["user_id"])
    if user is None:
        return None, None, ("unknown_user", 401)

    # If the authenticator returned a user handle it must identify the same
    # account that owns the credential (usernameless login).
    handle = user_handle_b64(credential)
    if handle:
        expected = bytes_to_base64url(user["webauthn_user_id"])
        if not constant_time(handle, expected):
            return None, None, ("user_handle_mismatch", 401)

    # Synced passkeys may not maintain a globally monotonic counter.  Let the
    # library skip its strict comparison for a credential already marked as
    # backup-eligible, then apply AuthLab's policy below.
    synced = cred["kind"] == "platform" and bool(cred["backup_eligible"])
    try:
        verified = check_authentication(
            credential, flow["challenge"], cred["public_key"],
            cred["sign_count"], origins=origins,
            counter_floor=0 if synced else None,
        )
    except Exception as exc:
        return None, None, (f"authentication_verification_failed: {exc}", 401)

    device_type = _device_type(verified)
    backup_state = bool(verified.credential_backed_up)
    backup_eligible = bool(cred["backup_eligible"]) or device_type == "multi_device"

    # A roaming credential that claims backup eligibility is not a hardware
    # security key.  Reject it even if the signature is valid.
    if cred["kind"] == "roaming" and (backup_eligible or backup_state):
        return None, None, ("hardware_credential_is_backed_up", 401)

    policy = counter_policy or current_app.config["COUNTER_POLICY"]
    ok, counter_reason = counter_allows(
        cred["kind"], backup_eligible, cred["sign_count"],
        verified.new_sign_count, policy=policy,
    )
    if not ok:
        log_event("webauthn_login", user_id=cred["user_id"],
                  username=user["username"], method=DB_KIND_TO_FLOW[cred["kind"]],
                  success=False,
                  detail=f"counter: stored={cred['sign_count']} new={verified.new_sign_count}")
        return None, None, ("signature_counter_regression", 401)

    new_count = max(cred["sign_count"], verified.new_sign_count)
    execute(
        "UPDATE credentials SET sign_count = ?, backup_eligible = ?,"
        " backup_state = ?, last_used = ? WHERE id = ?",
        (new_count, int(backup_eligible), int(backup_state), now(), cred["id"]),
    )

    details = {
        "user": user,
        "credential": cred,
        "credential_id": cid,
        "kind": DB_KIND_TO_FLOW[cred["kind"]],
        "session_method": "passkey" if cred["kind"] == "platform" else "hardware_key",
        "counter": new_count,
        "counter_reason": counter_reason,
        "device_type": device_type,
        "backup_eligible": backup_eligible,
        "backup_state": backup_state,
        "origin": client_origin(credential),
    }
    return user, details, None


@bp.post("/webauthn/login/verify")
def login_verify():
    data = json_body()
    flow = consume_flow(data.get("flow_id"), "authenticate")
    credential = data.get("credential")
    if flow is None:
        return jsonify(ok=False, error="invalid_or_used_flow"), 400

    user, details, error = _finish_authentication(flow, credential)
    if error:
        reason, status = error
        log_event("webauthn_login",
                  user_id=flow["user_id"], method=flow["kind"],
                  success=False, detail=reason)
        return jsonify(ok=False, error=reason), status

    token = create_session(user["id"], details["session_method"])
    log_event("login", user_id=user["id"], username=user["username"],
              method=details["session_method"], success=True,
              detail=f"counter={details['counter']} ({details['counter_reason']}) "
                     f"be={details['backup_eligible']} bs={details['backup_state']}")
    resp = jsonify(
        ok=True, redirect="/dashboard", method=details["session_method"],
        username=user["username"], counter=details["counter"],
        counter_reason=details["counter_reason"],
        backup_eligible=details["backup_eligible"],
        backup_state=details["backup_state"],
    )
    return set_session_cookie(resp, token)


@bp.post("/lab/webauthn/login/verify")
def lab_login_verify():
    """Verifier used by the phishing proxy.

    ``policy=strict`` checks the configured origin.  ``policy=permissive``
    reproduces a real-world RP bug: it checks the signature and RP ID but
    trusts the origin embedded in clientDataJSON.  That is the difference
    between a passkey being phishing-resistant and merely phishing-resistant
    *if the RP is implemented correctly*.
    """
    if not current_app.config["LAB_MODE"]:
        abort(404)
    if request.headers.get("X-AuthLab-Lab") != current_app.config["LAB_TOKEN"]:
        abort(401)

    data = json_body()
    policy = data.get("policy", "strict")
    if policy not in ("strict", "permissive"):
        return jsonify(ok=False, error="invalid_policy"), 400
    flow = consume_flow(data.get("flow_id"), "authenticate")
    credential = data.get("credential")
    if flow is None:
        return jsonify(ok=False, error="invalid_or_used_flow"), 400

    origins = None
    if policy == "permissive":
        origin = client_origin(credential)
        if not origin:
            return jsonify(ok=False, error="missing_origin"), 400
        origins = [origin]

    user, details, error = _finish_authentication(
        flow, credential, origins=origins, counter_policy="permissive" if policy == "permissive" else None
    )
    if error:
        reason, status = error
        log_event("lab_webauthn_login", user_id=flow["user_id"],
                  method=f"{flow['kind']}:{policy}", success=False, detail=reason)
        return jsonify(ok=False, error=reason, policy=policy), status

    token = create_session(user["id"], details["session_method"])
    log_event("lab_webauthn_login", user_id=user["id"], username=user["username"],
              method=f"{flow['kind']}:{policy}", success=True,
              detail=f"origin={details['origin']} counter={details['counter']}")
    resp = jsonify(
        ok=True, policy=policy, username=user["username"],
        method=details["session_method"], origin=details["origin"],
        rp_id=current_app.config["RP_ID"], counter=details["counter"],
        backup_eligible=details["backup_eligible"],
        backup_state=details["backup_state"],
    )
    return set_session_cookie(resp, token)


@bp.post("/credentials/<int:credential_id>/revoke")
@require_login
def revoke_credential(credential_id: int):
    user = current_user()
    row = query_one(
        "SELECT * FROM credentials WHERE id = ? AND user_id = ?",
        (credential_id, user["user_id"]),
    )
    if row is None:
        return jsonify(ok=False, error="not_found"), 404
    execute("DELETE FROM credentials WHERE id = ?", (credential_id,))
    log_event("credential_revoked", user_id=user["user_id"],
              username=user["username"], method=DB_KIND_TO_FLOW[row["kind"]],
              success=True, detail=row["label"])
    return jsonify(ok=True)
