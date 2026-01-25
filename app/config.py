from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _format_deploy_tag(dt: datetime) -> str:
    return f"{dt.year % 100:02d}{dt.month:02d}{dt.day:02d}{dt.hour:02d}{dt.minute:02d}"


class Settings(BaseSettings):
    """HOTEL backend configuration.

    NOTE:
    - Loaded from environment (typically /etc/hotelapp/hotel.env mounted/loaded by compose).
    - Keep secrets out of repo.
    """

    model_config = SettingsConfigDict(
        env_prefix="HOTEL_",
        case_sensitive=False,
        extra="ignore",
    )

    app_version: str = "1.0.0"
    deploy_tag: str = Field(default_factory=lambda: _format_deploy_tag(datetime.now(timezone.utc)))

    # --- Core ---
    environment: Literal["dev", "prod"] = "prod"

    # Public base URL (used in templates / generating links)
    public_base_url: str = "https://hotel.hcasc.cz"

    # --- Database ---
    # In production use a full URL like:
    # postgresql+psycopg://hotel_user:...@postgres:5432/hotel_db
    database_url: str = Field(..., description="SQLAlchemy database URL")
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_pool_recycle_seconds: int = 1800

    # --- Admin auth (single password) ---
    # Store password hash (argon2/bcrypt) here. Never store plaintext.
    admin_password_hash: str = Field(..., min_length=20)

    # If you want to support first-run bootstrapping (optional):
    # Set HOTEL_ADMIN_PASSWORD_PLAINTEXT only temporarily and run a seed/rotate command.
    # This app will NOT accept plaintext for login.

    # --- Sessions & CSRF ---
    session_secret: str = Field(..., min_length=32)
    csrf_secret: str = Field(..., min_length=32)

    # Cookie flags
    session_cookie_name: str = "hotel_session"
    admin_session_cookie_name: str = "hotel_admin_session"
    admin_session_issued_cookie_name: str = "hotel_admin_session_issued"
    admin_session_ttl_minutes: int = 12 * 60
    session_cookie_secure: bool = True
    session_cookie_samesite: Literal["lax", "strict", "none"] = "none"
    session_max_age_seconds: int = 60 * 60 * 12

    # --- Media storage ---
    # Must be consistent with server path requirement:
    # /var/lib/hotelapp/media/
    media_root: str = "/var/lib/hotelapp/media"
    public_apk_path: str = "/var/www/hotelapp/download/app.apk"

    # --- Upload limits ---
    # Backend will enforce these limits; Nginx must also have client_max_body_size aligned.
    max_photos_per_report: int = 5
    max_photo_bytes: int = 3_500_000  # ~3.5 MB per photo after client compression
    max_request_bytes: int = 18_000_000  # total multipart size (rough cap)

    # Image processing
    thumbnail_max_size: int = 640
    jpeg_quality: int = 82

    # --- Polling / rate limiting (soft defaults; enforced by middleware) ---
    rate_limit_admin_login_per_minute: int = 10
    rate_limit_device_status_per_minute: int = 60
    rate_limit_device_challenge_per_minute: int = 60
    rate_limit_device_verify_per_minute: int = 30
    rate_limit_device_new_since_per_minute: int = 60
    rate_limit_report_create_per_minute: int = 30

    # --- Security headers / HSTS (also in Nginx) ---
    enable_hsts: bool = True

    # --- Breakfast (mail fetch) defaults (DB-config overrides later) ---
    # NOTE: Do NOT hardcode secrets in repo. These are only fallbacks if DB config is not used yet.
    breakfast_enabled: bool = True
    breakfast_imap_host: str = "mail.webglobe.cz"
    breakfast_imap_port: int = 993
    breakfast_imap_use_ssl: bool = True
    breakfast_imap_mailbox: str = "INBOX"
    breakfast_imap_username: str = ""  # e.g. recepce@hotelchodovasc.cz
    breakfast_imap_password: str = ""  # set via env or via admin DB config (next step)

    # Filters (soft)
    breakfast_from_contains: str = "better-hotel.com"
    breakfast_subject_contains: str = "přehled stravy"

    # Window + retry (local server time)
    breakfast_window_start: str = "02:00"  # HH:MM
    breakfast_window_end: str = "03:00"    # HH:MM
    breakfast_retry_minutes: int = 5

    # Where to archive/store PDFs (under MEDIA_ROOT)
    breakfast_storage_dir: str = "breakfast"

    # --- Logging ---
    log_level: str = "INFO"

    # --- Crypto (šifrování hesel v admin UI) ---
    crypto_secret: Optional[str] = None

    # --- Device activation / crypto ---
    # Supported signature algorithms. App will use what's available; server verifies.
    # Prefer Ed25519 if available.
    device_sig_alg: Literal["ed25519", "ecdsa_p256"] = "ed25519"

    # Challenge nonce parameters
    challenge_ttl_seconds: int = 120

    # Legacy/uppercase compatibility helpers
    @property
    def SESSION_SECRET(self) -> str:
        return self.session_secret

    @property
    def SESSION_COOKIE_NAME(self) -> str:
        return self.session_cookie_name

    @property
    def SESSION_MAX_AGE_SECONDS(self) -> int:
        return self.session_max_age_seconds

    @property
    def MEDIA_ROOT(self) -> str:
        return self.media_root

    @property
    def APP_VERSION(self) -> str:
        return self.app_version


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()  # type: ignore[call-arg]
        _validate_settings(_settings)
    return _settings


# Convenience alias for dependency injection in routers
Settings.from_env = staticmethod(get_settings)  # type: ignore[attr-defined]


def _validate_settings(s: Settings) -> None:
    # public_base_url must match canonical domain
    if s.public_base_url.rstrip("/") != "https://hotel.hcasc.cz":
        raise ValueError(
            "HOTEL_PUBLIC_BASE_URL must be exactly 'https://hotel.hcasc.cz' (canonical domain)."
        )

    # Media root must be absolute
    mr = Path(s.media_root)
    if not mr.is_absolute():
        raise ValueError("HOTEL_MEDIA_ROOT must be an absolute path")

    # Basic sanity
    if s.max_photos_per_report < 1 or s.max_photos_per_report > 5:
        raise ValueError("HOTEL_MAX_PHOTOS_PER_REPORT must be between 1 and 5")

    if s.jpeg_quality < 40 or s.jpeg_quality > 95:
        raise ValueError("HOTEL_JPEG_QUALITY must be between 40 and 95")


def ensure_dirs() -> None:
    """Create required directories if missing.

    Called during startup inside container. The host should mount /var/lib/hotelapp/media.
    """
    s = get_settings()
    root = Path(s.media_root)
    (root / "reports").mkdir(parents=True, exist_ok=True)
    (root / "tmp").mkdir(parents=True, exist_ok=True)
    (root / s.breakfast_storage_dir / "archive").mkdir(parents=True, exist_ok=True)


# Provide a module-level settings instance for legacy imports.
settings = get_settings()
