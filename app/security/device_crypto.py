from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from fastapi import HTTPException


class DeviceCryptoError(Exception):
    """Raised when device cryptographic verification fails."""


@dataclass(frozen=True)
class Challenge:
    nonce: str
    expires_at: int


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    # Add padding
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def generate_device_token(length_bytes: int = 32) -> str:
    """Random bearer token to be stored hashed server-side."""
    if length_bytes < 32:
        length_bytes = 32
    return _b64url_encode(secrets.token_bytes(length_bytes))


def hash_device_token(token: str, pepper: str) -> str:
    """Hash device token with a server-side pepper (HMAC-SHA256).

    We intentionally do NOT use a slow password hash for tokens because:
    - tokens are high-entropy random values
    - we need fast lookup and comparison

    Store only the hex digest in DB.
    """
    if not pepper or len(pepper) < 16:
        raise ValueError("DEVICE_TOKEN_PEPPER must be set and reasonably long")
    digest = hmac.new(pepper.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def generate_challenge(ttl_seconds: int = 120) -> Challenge:
    if ttl_seconds < 30:
        ttl_seconds = 30
    now = int(time.time())
    nonce = _b64url_encode(secrets.token_bytes(32))
    return Challenge(nonce=nonce, expires_at=now + ttl_seconds)


def is_challenge_expired(ch: Challenge, now: int | None = None) -> bool:
    if now is None:
        now = int(time.time())
    return now >= int(ch.expires_at)


def public_key_from_b64(public_key_b64: str, key_type: str):
    """Parse a public key as sent by Android.

    Supported key_type:
      - "ED25519": raw 32-byte public key
      - "ECDSA_P256": X9.62 uncompressed point format

    Notes:
    - Android Keystore supports ECDSA P-256 widely.
    - Ed25519 support depends on platform/provider; we support it here for completeness.
    """
    raw = _b64url_decode(public_key_b64)

    kt = (key_type or "").upper()
    if kt == "ED25519":
        if len(raw) != 32:
            raise DeviceCryptoError("Invalid ED25519 public key length")
        return ed25519.Ed25519PublicKey.from_public_bytes(raw)

    if kt in ("ECDSA_P256", "ECDSA", "P256"):
        # Expect uncompressed point 0x04 || X(32) || Y(32)
        if len(raw) != 65 or raw[0] != 0x04:
            raise DeviceCryptoError("Invalid ECDSA P-256 public key encoding")
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)

    raise DeviceCryptoError("Unsupported key_type")


def verify_signature(
    *,
    key_type: str,
    public_key_b64: str,
    message: bytes,
    signature_b64: str,
) -> bool:
    """Verify signature over message.

    signature_b64 formats:
      - ED25519: raw 64-byte signature
      - ECDSA P-256: ASN.1 DER signature (as produced by Java Signature "SHA256withECDSA")
    """
    pub = public_key_from_b64(public_key_b64, key_type)
    sig = _b64url_decode(signature_b64)

    kt = (key_type or "").upper()

    try:
        if kt == "ED25519":
            if len(sig) != 64:
                raise DeviceCryptoError("Invalid ED25519 signature length")
            pub.verify(sig, message)
            return True

        if kt in ("ECDSA_P256", "ECDSA", "P256"):
            pub.verify(sig, message, ec.ECDSA(hashes.SHA256()))
            return True

        raise DeviceCryptoError("Unsupported key_type")

    except InvalidSignature:
        return False


def build_verify_message(
    *,
    device_id: str,
    nonce: str,
    issued_at: int,
    audience: str = "hotel.hcasc.cz",
) -> bytes:
    """Deterministic message to be signed by Android.

    IMPORTANT: Do not sign free-form JSON; sign a stable canonical format.

    Format (UTF-8):
      hotel.hcasc.cz|device_id|nonce|issued_at

    audience binds the signature to this deployment (domain).
    """
    if not device_id:
        raise ValueError("device_id required")
    if not nonce:
        raise ValueError("nonce required")
    if issued_at <= 0:
        raise ValueError("issued_at required")

    s = f"{audience}|{device_id}|{nonce}|{issued_at}"
    return s.encode("utf-8")


def validate_verify_payload_times(
    *,
    challenge_expires_at: int,
    issued_at: int,
    now: int | None = None,
    max_clock_skew_seconds: int = 180,
) -> tuple[bool, str]:
    """Validate issued_at is reasonable and within challenge lifetime.

    Returns (ok, reason).
    """
    if now is None:
        now = int(time.time())

    if issued_at <= 0:
        return False, "invalid_issued_at"

    # issued_at must not be too far in the future
    if issued_at > now + max_clock_skew_seconds:
        return False, "issued_at_in_future"

    # issued_at must not be too old (stale replay)
    if issued_at < now - (max_clock_skew_seconds + 300):
        return False, "issued_at_too_old"

    # Must be within the current challenge validity window
    if issued_at > challenge_expires_at:
        return False, "challenge_expired"

    return True, "ok"


def compute_device_token_hash(token: str, pepper: str | None = None) -> str:
    """Backward-compatible hash for device tokens."""

    # If no pepper provided, fall back to deterministic SHA256.
    if not pepper:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()
    return hash_device_token(token, pepper)


def ensure_recent_nonce(device, nonce: bytes, *, max_age_seconds: int = 300) -> None:
    """Validate nonce matches last issued and is within allowed age."""

    expected_b64 = getattr(device, "last_challenge_nonce", None) or ""
    issued_at: datetime | None = getattr(device, "last_challenge_issued_at", None)
    if not expected_b64 or issued_at is None:
        raise HTTPException(status_code=403, detail="CHALLENGE_NOT_FOUND")

    try:
        expected_bytes = _b64url_decode(expected_b64)
    except Exception:
        expected_bytes = b""

    if not hmac.compare_digest(expected_bytes, nonce):
        raise HTTPException(status_code=403, detail="CHALLENGE_MISMATCH")

    now = datetime.now(UTC)
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=UTC)
    if now - issued_at > timedelta(seconds=max_age_seconds):
        raise HTTPException(status_code=403, detail="CHALLENGE_EXPIRED")


def verify_device_signature(public_key: bytes, nonce: bytes, signature: bytes, *, key_type: str = "ed25519") -> bool:
    """Verify signature over nonce using stored public key."""

    if not public_key or not signature or not nonce:
        return False

    kt = (key_type or "ed25519").lower()
    try:
        if kt == "ed25519":
            pub = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            pub.verify(signature, nonce)
            return True

        if kt in ("ecdsa", "ecdsa_p256", "p256"):
            pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
            pub.verify(signature, nonce, ec.ECDSA(hashes.SHA256()))
            return True
    except Exception:
        return False

    return False
