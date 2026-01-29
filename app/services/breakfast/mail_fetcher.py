from __future__ import annotations

import email
import imaplib
import logging
import os
import re
import tempfile
import unicodedata
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from email.message import Message
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.db.models import BreakfastDay, BreakfastEntry, BreakfastFetchStatus, BreakfastMailConfig
from app.db.session import SessionLocal
from app.security.crypto import Crypto
from app.services.breakfast.parser import format_text_summary, parse_breakfast_pdf

log = logging.getLogger("hotel.breakfast")


@dataclass(frozen=True)
class EffectiveBreakfastConfig:
    enabled: bool
    imap_host: str
    imap_port: int
    imap_use_ssl: bool
    imap_mailbox: str
    username: str
    password: str
    from_contains: str
    subject_contains: str
    window_start_hhmm: str
    window_end_hhmm: str
    retry_minutes: int


def _load_effective_config(db: Session) -> EffectiveBreakfastConfig:
    row = db.execute(select(BreakfastMailConfig).order_by(BreakfastMailConfig.id.asc())).scalars().first()

    if row:
        # Prefer encrypted password if present and CRYPTO_SECRET is set.
        password = row.password
        if getattr(row, "password_enc", None) and settings.crypto_secret:
            try:
                crypto = Crypto.from_secret(settings.crypto_secret)
                password = crypto.decrypt_str(row.password_enc)  # type: ignore[arg-type]
            except Exception:
                log.warning("Breakfast: encrypted heslo nelze dešifrovat, padám na plaintext.")

        # Map security to SSL flag
        security = (row.imap_security or "SSL").upper() if getattr(row, "imap_security", None) else "SSL"
        use_ssl = security == "SSL" or (security not in {"SSL", "STARTTLS", "PLAIN"})
        return EffectiveBreakfastConfig(
            enabled=bool(row.enabled),
            imap_host=row.imap_host,
            imap_port=int(row.imap_port),
            imap_use_ssl=use_ssl,
            imap_mailbox=row.imap_mailbox,
            username=row.username,
            password=password,
            from_contains=(row.filter_from or row.from_contains or "").strip() or "better-hotel.com",
            subject_contains=(row.filter_subject or row.subject_contains or "").strip() or "přehled stravy",
            window_start_hhmm=row.window_start.strftime("%H:%M"),
            window_end_hhmm=row.window_end.strftime("%H:%M"),
            retry_minutes=int(row.retry_minutes or 5),
        )

    # Fallback to env defaults (no secrets in repo; must be set in /etc/hotelapp/hotel.env)
    return EffectiveBreakfastConfig(
        enabled=bool(settings.breakfast_enabled),
        imap_host=settings.breakfast_imap_host,
        imap_port=int(settings.breakfast_imap_port),
        imap_use_ssl=bool(settings.breakfast_imap_use_ssl),
        imap_mailbox=settings.breakfast_imap_mailbox,
        username=settings.breakfast_imap_username,
        password=settings.breakfast_imap_password,
        from_contains=settings.breakfast_from_contains,
        subject_contains=settings.breakfast_subject_contains,
        window_start_hhmm=settings.breakfast_window_start,
        window_end_hhmm=settings.breakfast_window_end,
        retry_minutes=int(settings.breakfast_retry_minutes),
    )


def _imap_date(d: date) -> str:
    # IMAP4 SEARCH expects e.g. 22-Jan-2026
    return d.strftime("%d-%b-%Y")


def _decode_header_value(val: str | None) -> str:
    if not val:
        return ""
    parts = email.header.decode_header(val)
    out = []
    for p, enc in parts:
        if isinstance(p, bytes):
            out.append(p.decode(enc or "utf-8", errors="replace"))
        else:
            out.append(str(p))
    return "".join(out).strip()


def _normalize_match(s: str) -> str:
    base = unicodedata.normalize("NFKD", s or "")
    return "".join(ch for ch in base if not unicodedata.combining(ch)).lower().strip()


def _iter_pdf_attachments(msg: Message) -> list[tuple[str, bytes]]:
    found: list[tuple[str, bytes]] = []
    def _maybe_add(part: Message) -> None:
        ctype = (part.get_content_type() or "").lower()
        filename = _decode_header_value(part.get_filename() or "")
        if not filename:
            name_param = part.get_param("name")
            if isinstance(name_param, str):
                filename = _decode_header_value(name_param)
        is_pdf = filename.lower().endswith(".pdf") if filename else (ctype == "application/pdf")
        if not is_pdf:
            return
        payload = part.get_payload(decode=True) or b""
        if not filename:
            filename = "attachment.pdf"
        found.append((filename, payload))

    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            _maybe_add(part)
    else:
        _maybe_add(msg)
    return found


def _message_matches(msg: Message, from_contains: str, subject_contains: str) -> bool:
    from_h = _decode_header_value(msg.get("From"))
    subj = _decode_header_value(msg.get("Subject"))
    from_norm = _normalize_match(from_h)
    subj_norm = _normalize_match(subj)
    from_need = _normalize_match(from_contains)
    subject_need = _normalize_match(subject_contains)
    if from_need and from_need not in from_norm:
        return False
    if subject_need and subject_need not in subj_norm:
        return False
    return True


def _safe_filename(s: str) -> str:
    s2 = re.sub(r"[^a-zA-Z0-9._-]+", "_", s).strip("_")
    return s2 or "file"


def _media_root_with_fallback() -> Path:
    root = Path(settings.MEDIA_ROOT)
    try:
        root.mkdir(parents=True, exist_ok=True)
        test = root / ".__writetest"
        test.write_text("ok", encoding="utf-8")
        test.unlink(missing_ok=True)
        return root
    except PermissionError:
        fallback_env = os.getenv("HOTEL_MEDIA_ROOT_FALLBACK")
        fallback = Path(fallback_env) if fallback_env else Path(tempfile.gettempdir()) / "hotelapp" / "media"
        fallback.mkdir(parents=True, exist_ok=True)
        log.warning("MEDIA_ROOT %s není zapisovatelný, ukládám do fallback cesty %s", root, fallback)
        return fallback


def _store_pdf_bytes(pdf_bytes: bytes, day: date, source_uid: str | None) -> tuple[str, str]:
    """
    Store:
      (a) day copy:   MEDIA_ROOT/breakfast/YYYY-MM-DD.pdf
      (b) archive:    MEDIA_ROOT/breakfast/archive/YYYY/MM/DD/<uid>.pdf
    Returns: (rel_day_path, rel_archive_path)
    """
    root = _media_root_with_fallback()
    base = Path(settings.breakfast_storage_dir)

    day_rel = base / f"{day.isoformat()}.pdf"
    archive_rel = base / "archive" / f"{day.year:04d}" / f"{day.month:02d}" / f"{day.day:02d}"
    uid_part = _safe_filename(source_uid or f"{int(datetime.now().timestamp())}")
    archive_rel = archive_rel / f"{uid_part}.pdf"

    day_abs = root / day_rel
    archive_abs = root / archive_rel

    day_abs.parent.mkdir(parents=True, exist_ok=True)
    archive_abs.parent.mkdir(parents=True, exist_ok=True)

    day_abs.write_bytes(pdf_bytes)
    archive_abs.write_bytes(pdf_bytes)

    return str(day_rel), str(archive_rel)


def _upsert_breakfast_day(
    db: Session,
    day: date,
    pdf_rel: str,
    archive_rel: str,
    source_uid: str | None,
    source_message_id: str | None,
    source_subject: str | None,
    text_summary: str,
    entries: list[tuple[str, int, str | None]],
) -> None:
    existing = db.execute(select(BreakfastDay).where(BreakfastDay.day == day)).scalars().one_or_none()
    if existing is None:
        existing = BreakfastDay(
            day=day,
            pdf_path=pdf_rel,
            pdf_archive_path=archive_rel,
            source_uid=source_uid,
            source_message_id=source_message_id,
            source_subject=source_subject,
            text_summary=text_summary,
        )
        db.add(existing)
        db.flush()
    else:
        # Keep latest fetch (overwrite paths + summary + source fields)
        existing.pdf_path = pdf_rel
        existing.pdf_archive_path = archive_rel
        existing.source_uid = source_uid
        existing.source_message_id = source_message_id
        existing.source_subject = source_subject
        existing.text_summary = text_summary
        # Replace entries
        existing.entries.clear()
        db.flush()

    for item in entries:
        room = None
        count = None
        guest_name = None
        note = None
        try:
            if isinstance(item, dict):
                room = str(item.get("room") or item.get("device_id") or "").strip()
                count = item.get("count") or item.get("breakfast_count")
                guest_name = item.get("guest_name") or item.get("guestName") or item.get("name")
                note = item.get("note")
            else:
                try:
                    room, count, guest_name, note = item
                except ValueError:
                    room, count, guest_name = item
        except ValueError:
            try:
                room, count = item  # guest name chybí, doplníme None
            except Exception:
                log.warning("Breakfast entry malformed (len/shape): %r", item)
                continue
        except Exception as e:
            log.warning("Breakfast entry malformed: %r (%s)", item, e)
            continue
        if room is None or count is None:
            log.warning("Breakfast entry missing room/count: %r", item)
            continue
        note_val = None
        if isinstance(note, str):
            note_val = note.strip() or None
        elif note is not None:
            try:
                note_val = str(note).strip() or None
            except Exception:
                note_val = None
        existing.entries.append(
            BreakfastEntry(
                room=room,
                breakfast_count=count,
                guest_name=guest_name or None,
                note=note_val,
            )
        )

    db.commit()


class BreakfastMailFetcher:
    """
    Backend service:
      - Connect via IMAP
      - Find email whose PDF contains 'Přehled stravy <today>'
      - Store original PDF + normalized breakfast entries (only breakfast_count > 0)
    """

    def fetch_and_store_for_day(self, target_day: date) -> bool:
        db = SessionLocal()
        try:
            status_row = db.execute(select(BreakfastFetchStatus).where(BreakfastFetchStatus.id == 1)).scalars().one_or_none()
            if status_row is None:
                status_row = BreakfastFetchStatus(id=1)
                db.add(status_row)
                db.commit()
                db.refresh(status_row)

            status_row.last_attempt_at = datetime.now(UTC)
            status_row.last_error = None
            db.add(status_row)
            db.commit()

            cfg = _load_effective_config(db)
            if not cfg.enabled:
                log.info("Breakfast fetcher disabled.")
                return False
            if not cfg.username or not cfg.password:
                log.warning("Breakfast fetcher has no credentials configured (username/password empty).")
                return False

            # Idempotency shortcut: if we already have breakfast_days row for today, do nothing.
            already = db.execute(select(BreakfastDay).where(BreakfastDay.day == target_day)).scalars().one_or_none()
            if already is not None:
                log.info("Breakfast for %s already present in DB, skipping fetch.", target_day.isoformat())
                return True

            res = self._fetch_pdf_for_day(cfg, target_day)
            if res is None:
                return False

            pdf_bytes, source_uid, msgid, subject = res
            parsed_day, rows = parse_breakfast_pdf(pdf_bytes)
            if parsed_day != target_day:
                log.warning("Fetched PDF day=%s does not match target=%s", parsed_day, target_day)
                return False

            text_summary = format_text_summary(parsed_day, rows)
            pdf_rel, archive_rel = _store_pdf_bytes(pdf_bytes, parsed_day, source_uid)

            entries = [
                (r.room, r.breakfast_count, r.guest_name)
                for r in rows
                if r.breakfast_count > 0
            ]
            _upsert_breakfast_day(
                db=db,
                day=parsed_day,
                pdf_rel=pdf_rel,
                archive_rel=archive_rel,
                source_uid=source_uid,
                source_message_id=msgid,
                source_subject=subject,
                text_summary=text_summary,
                entries=entries,
            )

            log.info("Breakfast stored for %s: %d rooms", parsed_day.isoformat(), len(entries))
            status_row.last_success_at = datetime.now(UTC)
            db.add(status_row)
            db.commit()
            return True
        except Exception:
            db.rollback()
            log.exception("Breakfast fetch/store failed.")
            try:
                status_row = db.execute(select(BreakfastFetchStatus).where(BreakfastFetchStatus.id == 1)).scalars().one_or_none()
                if status_row:
                    status_row.last_error = "Fetch/store failed"
                    db.add(status_row)
                    db.commit()
            except Exception:
                pass
            return False
        finally:
            db.close()

    def _fetch_pdf_for_day(
        self, cfg: EffectiveBreakfastConfig, target_day: date
    ) -> tuple[bytes, str | None, str | None, str | None] | None:
        """
        Returns (pdf_bytes, imap_uid, message_id, subject) if found.
        """
        imap: imaplib.IMAP4 | imaplib.IMAP4_SSL
        if cfg.imap_use_ssl:
            imap = imaplib.IMAP4_SSL(cfg.imap_host, cfg.imap_port)
        else:
            imap = imaplib.IMAP4(cfg.imap_host, cfg.imap_port)

        try:
            imap.login(cfg.username, cfg.password)
            imap.select(cfg.imap_mailbox)

            # Search from yesterday (mail often arrives around ~22:00 the day before).
            since = target_day - timedelta(days=1)
            typ, data = imap.search(None, "SINCE", _imap_date(since))
            if typ != "OK" or not data or not data[0]:
                return None

            ids = data[0].split()
            # newest first
            for msg_id in reversed(ids):
                typ2, raw = imap.fetch(msg_id, "(RFC822)")
                if typ2 != "OK" or not raw or not raw[0]:
                    continue

                # raw[0] is (b'123 (RFC822 {..}', b'...bytes...')
                msg_bytes = raw[0][1]
                msg = email.message_from_bytes(msg_bytes)

                if not _message_matches(msg, cfg.from_contains, cfg.subject_contains):
                    continue

                attachments = _iter_pdf_attachments(msg)
                if not attachments:
                    continue

                subject = _decode_header_value(msg.get("Subject"))
                message_id = _decode_header_value(msg.get("Message-ID"))
                uid = msg_id.decode("ascii", errors="replace") if isinstance(msg_id, (bytes, bytearray)) else str(msg_id)

                for fname, pdf_bytes in attachments:
                    try:
                        pdf_day, _rows = parse_breakfast_pdf(pdf_bytes)
                    except Exception:
                        continue
                    if pdf_day == target_day:
                        log.info("Found breakfast PDF for %s (uid=%s, file=%s)", target_day, uid, fname)
                        return (pdf_bytes, uid, message_id, subject)

            return None
        finally:
            try:
                imap.logout()
            except Exception:
                pass
