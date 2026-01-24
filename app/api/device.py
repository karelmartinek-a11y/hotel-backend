from __future__ import annotations

import base64
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from pydantic.aliases import AliasChoices
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.config import Settings
from app.db.models import Device, DeviceStatus
from app.security.device_crypto import compute_device_token_hash

router = APIRouter(tags=["device"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _b64decode_any(value: str) -> bytes:
    v = (value or "").strip()
    if not v:
        raise HTTPException(status_code=400, detail="Missing base64 value")
    try:
        return base64.b64decode(v, validate=True)
    except Exception:
        # urlsafe variant (may omit padding)
        pad = "=" * ((4 - (len(v) % 4)) % 4)
        try:
            return base64.urlsafe_b64decode((v + pad).encode("ascii"))
        except Exception as e:
            raise HTTPException(status_code=400, detail="Invalid base64") from e


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _load_public_key(public_key_raw: str) -> tuple[bytes, str]:
    """Return (DER SubjectPublicKeyInfo bytes, alg label)."""
    raw = (public_key_raw or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Missing public key")

    key = None
    if "BEGIN PUBLIC KEY" in raw:
        try:
            key = serialization.load_pem_public_key(raw.encode("utf-8"))
        except Exception as e:
            raise HTTPException(status_code=400, detail="Invalid public key") from e
    else:
        key_bytes = _b64decode_any(raw)
        # Try DER SPKI first.
        try:
            key = serialization.load_der_public_key(key_bytes)
        except Exception:
            # Try raw uncompressed EC point for P-256 (0x04 + X + Y).
            try:
                key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key_bytes)
            except Exception as e:
                raise HTTPException(status_code=400, detail="Invalid public key") from e

    if isinstance(key, ec.EllipticCurvePublicKey):
        alg = "ECDSA_P256"
    elif isinstance(key, ed25519.Ed25519PublicKey):
        alg = "ED25519"
    else:
        raise HTTPException(status_code=400, detail="Unsupported public key type")

    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return der, alg


def _verify_signature(*, public_key_der: bytes, nonce: bytes, signature: bytes, alg: str | None) -> bool:
    try:
        key = serialization.load_der_public_key(public_key_der)
    except Exception:
        return False

    alg_n = (alg or "").upper()
    try:
        if isinstance(key, ec.EllipticCurvePublicKey) or alg_n in {"ECDSA_P256", "ECDSA", "P256"}:
            if not isinstance(key, ec.EllipticCurvePublicKey):
                return False
            key.verify(signature, nonce, ec.ECDSA(hashes.SHA256()))
            return True
        if isinstance(key, ed25519.Ed25519PublicKey) or alg_n in {"ED25519"}:
            if not isinstance(key, ed25519.Ed25519PublicKey):
                return False
            key.verify(signature, nonce)
            return True
    except Exception:
        return False

    return False


def _get_device_by_id(db: Session, device_id: str) -> Device | None:
    return db.execute(select(Device).where(Device.device_id == device_id)).scalar_one_or_none()


def _require_device_id(device_id: str | None, x_device_id: str | None) -> str:
    did = (device_id or "").strip() or (x_device_id or "").strip()
    if not did:
        raise HTTPException(status_code=400, detail="Missing device_id")
    if len(did) < 8 or len(did) > 128:
        raise HTTPException(status_code=400, detail="Invalid device_id")
    return did


class DeviceRegisterIn(BaseModel):
    model_config = {"populate_by_name": True, "extra": "ignore"}

    device_id: str = Field(
        validation_alias=AliasChoices("device_id", "deviceId"),
        min_length=8,
        max_length=128,
    )
    display_name: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("display_name", "displayName"),
        min_length=1,
        max_length=120,
    )
    public_key: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("device_public_key", "publicKey", "public_key", "public_key_b64", "public_key_b64"),
    )
    device_info: Optional[Any] = Field(default=None, validation_alias=AliasChoices("device_info", "deviceInfo"))


class DeviceStatusOut(BaseModel):
    status: str
    activatedAt: Optional[str] = None
    display_name: Optional[str] = None
    device_id: Optional[str] = None


class DeviceChallengeIn(BaseModel):
    model_config = {"populate_by_name": True, "extra": "ignore"}

    device_id: str = Field(validation_alias=AliasChoices("device_id", "deviceId"), min_length=8, max_length=128)


class DeviceChallengeOut(BaseModel):
    nonce: str
    issuedAt: str
    challenge: str


class DeviceVerifyIn(BaseModel):
    model_config = {"populate_by_name": True, "extra": "ignore"}

    nonce: str = Field(min_length=8, validation_alias=AliasChoices("nonce", "challenge"))
    signature: str = Field(min_length=8)
    device_id: Optional[str] = Field(default=None, validation_alias=AliasChoices("device_id", "deviceId"))


class DeviceVerifyOut(BaseModel):
    deviceToken: str
    status: str
    device_token: Optional[str] = None
    display_name: Optional[str] = None


@router.post("/device/register", response_model=DeviceStatusOut)
def device_register(payload: DeviceRegisterIn, request: Request, db: Session = Depends(get_db)):
    device = _get_device_by_id(db, payload.device_id)

    display_name = payload.display_name.strip() if payload.display_name else None
    if payload.display_name is not None and not display_name:
        raise HTTPException(status_code=400, detail="display_name required")

    public_key_der = None
    public_key_alg = None
    if payload.public_key:
        public_key_der, public_key_alg = _load_public_key(payload.public_key)

    if device is None:
        device = Device(
            device_id=payload.device_id,
            status=DeviceStatus.PENDING,
            public_key=public_key_der,
            public_key_alg=public_key_alg,
            display_name=display_name,
            last_seen_at=_now(),
        )
        db.add(device)
        db.commit()
    else:
        device.last_seen_at = _now()
        if public_key_der is not None and (device.public_key is None or device.public_key_alg is None):
            device.public_key = public_key_der
            device.public_key_alg = public_key_alg
        if display_name and not device.display_name:
            device.display_name = display_name
        db.add(device)
        db.commit()

    activated_at = device.activated_at.isoformat() if device.activated_at else None
    return DeviceStatusOut(
        status=device.status.value,
        activatedAt=activated_at,
        display_name=device.display_name,
        device_id=device.device_id,
    )


@router.get("/device/status", response_model=DeviceStatusOut)
def device_status(
    request: Request,
    device_id: Optional[str] = None,
    x_device_id: Optional[str] = Header(default=None, alias="X-Device-Id"),
    db: Session = Depends(get_db),
):
    did = _require_device_id(device_id, x_device_id)
    device = _get_device_by_id(db, did)

    if device is None:
        # Compatibility with older Android builds: status call may be the first contact.
        device = Device(
            device_id=did,
            status=DeviceStatus.PENDING,
            last_seen_at=_now(),
        )
        db.add(device)
        db.commit()
    else:
        device.last_seen_at = _now()
        db.add(device)
        db.commit()

    activated_at = device.activated_at.isoformat() if device.activated_at else None
    return DeviceStatusOut(status=device.status.value, activatedAt=activated_at)


@router.get("/device/{device_id}/status", response_model=DeviceStatusOut)
def device_status_compat(
    request: Request,
    device_id: str,
    db: Session = Depends(get_db),
):
    return device_status(request=request, device_id=device_id, db=db)


@router.post("/device/challenge", response_model=DeviceChallengeOut)
def device_challenge(
    payload: DeviceChallengeIn,
    request: Request,
    db: Session = Depends(get_db),
):
    device = _get_device_by_id(db, payload.device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not registered")
    if device.status == DeviceStatus.REVOKED:
        raise HTTPException(status_code=409, detail="Device revoked")
    if device.status != DeviceStatus.ACTIVE:
        raise HTTPException(status_code=409, detail="Device not active")
    if not device.public_key:
        raise HTTPException(status_code=409, detail="Device public key missing")

    nonce_bytes = secrets.token_bytes(32)
    nonce_b64 = _b64encode(nonce_bytes)

    device.last_challenge_nonce = nonce_b64
    device.last_challenge_issued_at = _now()
    device.last_seen_at = _now()
    db.add(device)
    db.commit()

    return DeviceChallengeOut(nonce=nonce_b64, issuedAt=_now().isoformat(), challenge=nonce_b64)


@router.post("/device/verify", response_model=DeviceVerifyOut)
def device_verify(
    payload: DeviceVerifyIn,
    request: Request,
    x_device_id: Optional[str] = Header(default=None, alias="X-Device-Id"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    did = _require_device_id(payload.device_id, x_device_id)
    device = _get_device_by_id(db, did)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not registered")

    if device.status == DeviceStatus.REVOKED:
        raise HTTPException(status_code=409, detail="Device revoked")
    if device.status != DeviceStatus.ACTIVE:
        raise HTTPException(status_code=409, detail="Device not active")

    if not device.public_key or not device.public_key_alg:
        raise HTTPException(status_code=409, detail="Device public key missing")

    if not device.last_challenge_nonce or not device.last_challenge_issued_at:
        raise HTTPException(status_code=403, detail="Challenge not found")

    try:
        expected_nonce = _b64decode_any(device.last_challenge_nonce)
    except HTTPException:
        expected_nonce = b""

    nonce_bytes = _b64decode_any(payload.nonce)
    if not hmac.compare_digest(expected_nonce, nonce_bytes):
        raise HTTPException(status_code=403, detail="Challenge mismatch")

    issued_at = device.last_challenge_issued_at
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=timezone.utc)
    if _now() - issued_at > timedelta(minutes=5):
        raise HTTPException(status_code=403, detail="Challenge expired")

    sig_bytes = _b64decode_any(payload.signature)
    if not _verify_signature(
        public_key_der=device.public_key,
        nonce=nonce_bytes,
        signature=sig_bytes,
        alg=device.public_key_alg,
    ):
        raise HTTPException(status_code=403, detail="Invalid signature")

    token = secrets.token_urlsafe(48)
    device.token_hash = compute_device_token_hash(token)
    device.last_challenge_nonce = None
    device.last_challenge_issued_at = None
    device.last_seen_at = _now()
    db.add(device)
    db.commit()

    return DeviceVerifyOut(
        deviceToken=token,
        status=device.status.value,
        device_token=token,
        display_name=device.display_name,
    )
