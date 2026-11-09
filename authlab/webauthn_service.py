"""Thin, explicit wrapper around py_webauthn.

Keeping every verification parameter visible makes the protocol experiments
reproducible: strict origin checking, user-verification requirements, and the
signature-counter policy are all chosen here, not hidden in a framework.
"""
from __future__ import annotations

import json

from flask import current_app
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from .security import parse_client_data


def registration_options(user, kind: str, exclude_credential_ids: list[str]) -> dict:
    """Build creation options for ``kind`` = ``passkey`` or ``hardware``."""
    platform = kind == "passkey"
    selection = AuthenticatorSelectionCriteria(
        authenticator_attachment=(
            AuthenticatorAttachment.PLATFORM
            if platform
            else AuthenticatorAttachment.CROSS_PLATFORM
        ),
        resident_key=(
            ResidentKeyRequirement.REQUIRED
            if platform
            else ResidentKeyRequirement.PREFERRED
        ),
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    exclude = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(cid))
        for cid in exclude_credential_ids
    ]
    options = generate_registration_options(
        rp_id=current_app.config["RP_ID"],
        rp_name=current_app.config["RP_NAME"],
        user_id=user["webauthn_user_id"],
        user_name=user["username"],
        user_display_name=user["username"],
        timeout=60000,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=selection,
        exclude_credentials=exclude,
    )
    return json.loads(options_to_json(options))


def authentication_options(kind: str, credentials: list) -> dict:
    """Build request options.

    Passkeys use an empty allow-list (discoverable/usernameless login).  A
    hardware key normally has a non-resident credential, so the username step
    supplies its credential IDs.
    """
    platform = kind == "passkey"
    allow = None
    if not platform and credentials:
        allow = [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(row["credential_id"]))
            for row in credentials
        ]
    options = generate_authentication_options(
        rp_id=current_app.config["RP_ID"],
        timeout=60000,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return json.loads(options_to_json(options))


def check_registration(credential: dict, challenge_b64: str,
                       origins: list[str] | None = None):
    return verify_registration_response(
        credential=credential,
        expected_challenge=base64url_to_bytes(challenge_b64),
        expected_rp_id=current_app.config["RP_ID"],
        expected_origin=origins or current_app.config["ORIGINS"],
        require_user_presence=True,
        require_user_verification=True,
    )


def check_authentication(credential: dict, challenge_b64: str,
                         public_key: bytes, sign_count: int,
                         origins: list[str] | None = None,
                         counter_floor: int | None = None):
    """Verify an assertion.

    py_webauthn v3 enforces a strictly increasing counter whenever either
    side is non-zero.  Synced passkeys are allowed to report a non-monotonic
    (often zero) counter, so for those credentials the library's counter check
    is disabled by presenting it with a floor of 0; AuthLab then applies its
    explicit policy in ``counter_allows``.
    """
    return verify_authentication_response(
        credential=credential,
        expected_challenge=base64url_to_bytes(challenge_b64),
        expected_rp_id=current_app.config["RP_ID"],
        expected_origin=origins or current_app.config["ORIGINS"],
        credential_public_key=public_key,
        credential_current_sign_count=(
            sign_count if counter_floor is None else counter_floor
        ),
        require_user_verification=True,
    )


def credential_id_of(credential: dict) -> str | None:
    cid = credential.get("id") if isinstance(credential, dict) else None
    if not cid:
        raw = credential.get("rawId") if isinstance(credential, dict) else None
        cid = raw
    return cid


def client_origin(credential: dict) -> str | None:
    return parse_client_data(credential).get("origin")


def client_type(credential: dict) -> str | None:
    return parse_client_data(credential).get("type")


def user_handle_b64(credential: dict) -> str | None:
    handle = (credential.get("response") or {}).get("userHandle")
    return handle or None


def counter_allows(kind: str, backup_eligible: bool, stored: int, new: int,
                   policy: str = "strict") -> tuple[bool, str]:
    """Decide whether a signature counter is acceptable.

    Strict hardware policy rejects non-increasing counters (clone signal).
    Synced passkeys are exempt because the sync fabric may not maintain a
    globally monotonic counter; this is a deliberate security/usability
    trade-off documented in the report.
    """
    if new > stored:
        return True, "monotonic"
    if kind == "platform" and backup_eligible:
        return True, "synced_non_monotonic"
    if policy == "permissive":
        return True, "permissive"
    if stored == 0 and new == 0 and kind == "platform":
        return True, "platform_zero"
    return False, "counter_regression"


def summarize_verified_registration(verified) -> dict:
    device_type = str(getattr(verified.credential_device_type, "value",
                              verified.credential_device_type))
    return {
        "credential_id": bytes_to_base64url(verified.credential_id),
        "sign_count": verified.sign_count,
        "aaguid": str(verified.aaguid),
        "fmt": str(getattr(verified.fmt, "value", verified.fmt)),
        "user_verified": bool(verified.user_verified),
        "device_type": device_type,
        # py_webauthn exposes the BE flag as the credential device type and
        # the BS flag as ``credential_backed_up``; they are not the same bit.
        "backup_eligible": device_type == "multi_device",
        "backup_state": bool(verified.credential_backed_up),
    }


def summarize_verified_authentication(verified) -> dict:
    return {
        "new_sign_count": verified.new_sign_count,
        "device_type": str(getattr(verified.credential_device_type, "value",
                                   verified.credential_device_type)),
        "backup_state": bool(verified.credential_backed_up),
        "user_verified": bool(verified.user_verified),
    }
