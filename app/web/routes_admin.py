from __future__ import annotations

import email
import imaplib
from dataclasses import dataclass
from datetime import date, datetime, timedelta, time
from email.header import decode_header
from typing import Any, Optional

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.models import BreakfastDay, BreakfastFetchStatus, BreakfastMailConfig
from app.db.session import get_db
from app.security.admin_auth import AdminAuthError, admin_require, admin_session_is_authenticated
from app.security.csrf import csrf_protect, csrf_token_ensure
from app.security.crypto import Crypto
from app.services.breakfast.mail_fetcher import (
    _imap_date,
    _iter_pdf_attachments,
    _message_matches,
    _store_pdf_bytes,
    _upsert_breakfast_day,
    parse_breakfast_pdf,
)
from app.services.breakfast.parser import format_text_summary

router = APIRouter()
templates = Jinja2Templates(directory="app/web/templates")


def _human(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _ensure_cfg(db: Session) -> BreakfastMailConfig:
    cfg = db.execute(select(BreakfastMailConfig).order_by(BreakfastMailConfig.id.asc())).scalars().first()
    if cfg is None:
        cfg = BreakfastMailConfig()
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


def _ensure_status(db: Session) -> BreakfastFetchStatus:
    st = db.execute(select(BreakfastFetchStatus).where(BreakfastFetchStatus.id == 1)).scalars().one_or_none()
    if st is None:
        st = BreakfastFetchStatus(id=1)
        db.add(st)
        db.commit()
        db.refresh(st)
    return st


def _decode_mime(value: str) -> str:
    parts = decode_header(value)
    out = ""
    for txt, enc in parts:
        if isinstance(txt, bytes):
            out += txt.decode(enc or "utf-8", errors="replace")
        else:
            out += txt
    return out


def _imap_connect(cfg: BreakfastMailConfig) -> imaplib.IMAP4:
    security = (cfg.imap_security or "SSL").upper()
    if security == "SSL":
        return imaplib.IMAP4_SSL(cfg.imap_host, int(cfg.imap_port))
    client = imaplib.IMAP4(cfg.imap_host, int(cfg.imap_port))
    if security == "STARTTLS":
        client.starttls()
    return client


def _imap_search_latest(client: imaplib.IMAP4, cfg: BreakfastMailConfig) -> tuple[bool, str, list[str]]:
    client.select(cfg.imap_mailbox or "INBOX")
    typ, data = client.search(None, "ALL")
    if typ != "OK":
        return False, "IMAP SEARCH selhalo.", []

    msg_ids = data[0].split()
    if not msg_ids:
        return False, "Mailbox je prázdný.", []

    for mid in reversed(msg_ids[-200:]):
        typ, msg_data = client.fetch(mid, "(RFC822)")
        if typ != "OK" or not msg_data or not msg_data[0]:
            continue
        raw = msg_data[0][1]
        m = email.message_from_bytes(raw)

        subj = _decode_mime(m.get("Subject", "") or "")
        frm = _decode_mime(m.get("From", "") or "")

        if cfg.filter_subject and cfg.filter_subject.lower() not in subj.lower():
            continue
        if cfg.filter_from and cfg.filter_from.lower() not in frm.lower():
            continue

        attachments: list[str] = []
        for part in m.walk():
            disp = part.get("Content-Disposition", "") or ""
            if "attachment" not in disp.lower():
                continue
            filename = part.get_filename()
            if filename:
                attachments.append(_decode_mime(filename))
            else:
                attachments.append("(attachment)")

        return True, f"Match: {subj or '(bez subjectu)'} / {frm or '(bez From)'}", attachments

    return False, "Nenalezen e-mail dle filtrů.", []


def _parse_hhmm(value: str, default: str) -> time:
    text = (value or default).strip()
    try:
        hh, mm = text.split(":")
        return time(int(hh), int(mm))
    except Exception:
        return time.fromisoformat(default if ":" in default else "02:00")


@router.get("/admin/breakfast", response_class=HTMLResponse)
def admin_breakfast_page(
    request: Request,
    db: Session = Depends(get_db),
):
    try:
        if not admin_session_is_authenticated(request):
            return RedirectResponse("/admin/login", status_code=303)
        cfg = _ensure_cfg(db)
        st = _ensure_status(db)
    except AdminAuthError:
        return RedirectResponse("/admin/login", status_code=303)

    diag = {
        "last_attempt_at_human": _human(st.last_attempt_at),
        "last_success_at_human": _human(st.last_success_at),
        "last_error": st.last_error,
    }

    return templates.TemplateResponse(
        "admin_breakfast.html",
        {
            "request": request,
            "active_nav": "breakfast",
            "csrf_token": csrf_token_ensure(request),
            "cfg": cfg,
            "diag": diag,
            "flash": request.session.pop("flash", None) if hasattr(request, "session") else None,
            "test": None,
        },
    )


@router.post("/admin/breakfast/save")
def admin_breakfast_save(
    request: Request,
    section: str = Form("mail"),
    imap_host: str = Form(""),
    imap_port: int = Form(993),
    imap_security: str = Form("SSL"),
    imap_mailbox: str = Form("INBOX"),
    imap_username: str = Form(""),
    imap_password: str = Form(""),
    filter_from: str = Form(""),
    filter_subject: str = Form(""),
    window_start: str = Form("02:00"),
    window_end: str = Form("03:00"),
    retry_minutes: int = Form(5),
    db: Session = Depends(get_db),
):
    try:
        if not admin_session_is_authenticated(request):
            return RedirectResponse("/admin/login", status_code=303)
        csrf_protect(request)
        cfg = _ensure_cfg(db)
        settings = get_settings()
    except AdminAuthError:
        return RedirectResponse("/admin/login", status_code=303)

    if section == "window":
        cfg.window_start = _parse_hhmm(window_start, "02:00")
        cfg.window_end = _parse_hhmm(window_end, "03:00")
        cfg.retry_minutes = int(retry_minutes or 5)
    else:
        cfg.imap_host = (imap_host or "").strip()
        cfg.imap_port = int(imap_port or 993)
        cfg.imap_security = (imap_security or "SSL").strip().upper()
        cfg.imap_use_ssl = cfg.imap_security == "SSL"
        cfg.imap_mailbox = (imap_mailbox or "INBOX").strip() or "INBOX"
        cfg.username = (imap_username or "").strip()
        cfg.filter_from = (filter_from or "").strip() or None
        cfg.from_contains = cfg.filter_from or cfg.from_contains
        cfg.filter_subject = (filter_subject or "").strip() or None
        cfg.subject_contains = cfg.filter_subject or cfg.subject_contains

        if imap_password:
            if not settings.crypto_secret:
                request.session["flash"] = {
                    "type": "error",
                    "message": "CRYPTO_SECRET není nastaven, heslo nelze uložit šifrovaně.",
                }
                return RedirectResponse("/admin/breakfast", status_code=303)
            crypto = Crypto.from_secret(settings.crypto_secret)
            cfg.password_enc = crypto.encrypt_str(imap_password)
            cfg.password = ""  # plaintext nechceme držet

    cfg.updated_at = datetime.now()
    db.add(cfg)
    db.commit()

    request.session["flash"] = {"type": "success", "message": "Uloženo."}
    return RedirectResponse("/admin/breakfast", status_code=303)


@dataclass
class TestResult:
    connected: bool
    found: bool
    message: str
    attachments: list[str]
    processed_days: list[str]
    errors: list[str]


@router.post("/admin/breakfast/upload", response_class=JSONResponse)
def admin_breakfast_upload(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    try:
        if not admin_session_is_authenticated(request):
            return JSONResponse({"ok": False, "error": "Not authenticated"}, status_code=401)
        csrf_protect(request)
    except AdminAuthError:
        return JSONResponse({"ok": False, "error": "Not authenticated"}, status_code=401)

    steps: list[str] = []
    try:
        filename = (file.filename or "").strip()
        content_type = (file.content_type or "").lower()
        if not filename.lower().endswith(".pdf") and "pdf" not in content_type:
            raise ValueError("Očekávám PDF soubor (.pdf).")

        pdf_bytes = file.file.read()
        if not pdf_bytes:
            raise ValueError("Soubor je prázdný.")
        steps.append("Upload OK.")

        steps.append("Zpracovávám PDF...")
        parsed_day, rows = parse_breakfast_pdf(pdf_bytes)
        steps.append(f"Nalezen den {parsed_day.isoformat()}, položky: {len(rows)}.")

        text_summary = format_text_summary(parsed_day, rows)
        pdf_rel, archive_rel = _store_pdf_bytes(pdf_bytes, parsed_day, source_uid="manual-upload")
        entries = [(r.room, r.breakfast_count) for r in rows if r.breakfast_count > 0]
        _upsert_breakfast_day(
            db=db,
            day=parsed_day,
            pdf_rel=pdf_rel,
            archive_rel=archive_rel,
            source_uid="manual-upload",
            source_message_id=None,
            source_subject="Ruční upload PDF",
            text_summary=text_summary,
            entries=entries,
        )
        steps.append("Zapsáno OK (existující den přepsán).")

        return JSONResponse(
            {
                "ok": True,
                "day": parsed_day.isoformat(),
                "entries": len(entries),
                "total_rows": len(rows),
                "steps": steps,
            }
        )
    except Exception as e:
        steps.append(f"Chyba: {e}")
        return JSONResponse({"ok": False, "error": str(e), "steps": steps}, status_code=400)


def _list_mailboxes(client: imaplib.IMAP4) -> list[str]:
    typ, data = client.list()
    if typ != "OK" or not data:
        return []
    boxes: list[str] = []
    for raw in data:
        if not raw:
            continue
        decoded = raw.decode(errors="ignore")
        # Typical format: '(\\HasNoChildren) "/" "INBOX/Sub Folder"'
        name = None
        if '"' in decoded:
            try:
                name = decoded.split('"')[-2]
            except Exception:
                name = None
        if not name:
            name = decoded.split()[-1]
        if name:
            boxes.append(name)
    return boxes


def _process_history(client: imaplib.IMAP4, db: Session, cfg: BreakfastMailConfig, days_back: int, steps: list[str]) -> TestResult:
    today = date.today()
    oldest = today - timedelta(days=days_back)

    existing_message_ids = {
        (row[0] or "").strip()
        for row in db.execute(select(BreakfastDay.source_message_id).where(BreakfastDay.source_message_id != None)).all()  # noqa: E711
        if row and row[0]
    }

    found_days: dict[date, list[tuple[bytes, str | None, str | None]]] = {}
    attachments_info: list[str] = []
    stats = {
        "boxes": 0,
        "messages": 0,
        "filtered": 0,
        "no_pdf": 0,
        "parse_fail": 0,
        "pdfs": 0,
    }

    mailboxes = _list_mailboxes(client) or [cfg.imap_mailbox or "INBOX"]
    steps.append(
        f"Nalezeno {len(mailboxes)} složek, prohledávám od {oldest.isoformat()} do {today.isoformat()}: "
        + ", ".join(mailboxes)
    )

    for box in mailboxes:
        stats["boxes"] += 1
        typ = "NO"
        try:
            typ, _ = client.select(f'"{box}"')
            if typ != "OK":
                # fallback bez uvozovek, IMAP server mívá různé formáty
                typ, _ = client.select(box)
        except Exception as e:
            steps.append(f"Složka {box}: select selhalo ({e}), přeskočeno.")
            continue
        if typ != "OK":
            steps.append(f"Složka {box}: nelze otevřít (přeskakuji).")
            continue
        typ, data = client.search(None, "SINCE", _imap_date(oldest))
        if typ != "OK" or not data or not data[0]:
            # fallback ALL, někdy IMAP server SINCE filtruje jinak
            typ, data = client.search(None, "ALL")
            if typ != "OK" or not data or not data[0]:
                steps.append(f"Složka {box}: žádné zprávy.")
                continue
        ids = data[0].split()
        steps.append(f"Složka {box}: kontroluji {len(ids)} zpráv.")
        for msg_id in reversed(ids):
            stats["messages"] += 1
            typ2, raw = client.fetch(msg_id, "(RFC822)")
            if typ2 != "OK" or not raw or not raw[0]:
                continue
            msg_bytes = raw[0][1]
            msg = email.message_from_bytes(msg_bytes)
            if not _message_matches(msg, cfg.filter_from or "", cfg.filter_subject or ""):
                stats["filtered"] += 1
                continue
            message_id = _decode_mime(msg.get("Message-ID", "") or "")
            if message_id and message_id in existing_message_ids:
                steps.append(f"{box}: přeskakuji už zpracovaný Message-ID {message_id}.")
                continue

            atts = _iter_pdf_attachments(msg)
            for fname, pdf_bytes in atts:
                try:
                    pdf_day, rows = parse_breakfast_pdf(pdf_bytes)
                except Exception:
                    stats["parse_fail"] += 1
                    continue
                if pdf_day < oldest or pdf_day > today:
                    continue
                attachments_info.append(f"{box}: {fname} -> {pdf_day.isoformat()} (msgid={message_id or 'N/A'})")
                found_days.setdefault(pdf_day, []).append(
                    (pdf_bytes, message_id, _decode_mime(msg.get("Subject", "") or ""))
                )
                if message_id:
                    existing_message_ids.add(message_id)
                stats["pdfs"] += 1
            if not atts:
                stats["no_pdf"] += 1

    processed_days: list[str] = []
    errors: list[str] = []

    for d, metas in found_days.items():
        for pdf_bytes, message_id, subject in metas:
            try:
                parsed_day, rows = parse_breakfast_pdf(pdf_bytes)
                text_summary = ", ".join(f"Pokoj {r.room}: {r.breakfast_count}" for r in rows)
                pdf_rel, archive_rel = _store_pdf_bytes(pdf_bytes, parsed_day, source_uid=None)
                entries = [(r.room, r.breakfast_count) for r in rows if r.breakfast_count > 0]
                _upsert_breakfast_day(
                    db=db,
                    day=parsed_day,
                    pdf_rel=pdf_rel,
                    archive_rel=archive_rel,
                    source_uid=None,
                    source_message_id=message_id,
                    source_subject=subject,
                    text_summary=text_summary,
                    entries=entries,
                )
                processed_days.append(parsed_day.isoformat())
            except Exception as e:
                errors.append(f"{d.isoformat()}: {e}")

    total_pdf = sum(len(v) for v in found_days.values())
    found = total_pdf > 0
    msg = f"Nalezeno {total_pdf} PDF, zpracováno {len(processed_days)}."
    if errors:
        msg += f" Chyby: {len(errors)}."

    steps.append(
        f"Souhrn: složky {stats['boxes']}, zprávy {stats['messages']}, přes filtr {stats['filtered']}, "
        f"bez PDF {stats['no_pdf']}, parse chyby {stats['parse_fail']}, PDF {stats['pdfs']}."
    )

    return TestResult(
        connected=True,
        found=found,
        message=msg,
        attachments=attachments_info,
        processed_days=processed_days,
        errors=errors,
    )


@router.post("/admin/breakfast/test", response_class=JSONResponse)
def admin_breakfast_test(
    request: Request,
    db: Session = Depends(get_db),
):
    try:
        if not admin_session_is_authenticated(request):
            return JSONResponse({"ok": False, "error": "Not authenticated"}, status_code=401)
        csrf_protect(request)
        cfg = _ensure_cfg(db)
        st = _ensure_status(db)
        settings = get_settings()
    except AdminAuthError:
        return JSONResponse({"ok": False, "error": "Not authenticated"}, status_code=401)

    st.last_attempt_at = datetime.now()
    st.last_error = None
    db.add(st)
    db.commit()

    test = TestResult(connected=False, found=False, message="", attachments=[], processed_days=[], errors=[])
    password: Optional[str] = None
    steps: list[str] = []
    if cfg.password_enc and settings.crypto_secret:
        try:
            crypto = Crypto.from_secret(settings.crypto_secret)
            password = crypto.decrypt_str(cfg.password_enc)
        except Exception as e:
            st.last_error = f"Decrypt error: {e}"
            test.errors.append(st.last_error)
            steps.append(st.last_error)
    elif cfg.password:
        password = cfg.password

    try:
        steps.append("Připravuji připojení k IMAP.")
        if not password:
            raise RuntimeError("Heslo není nastaveno. Uložte konfiguraci s heslem a zkuste znovu.")
        if not cfg.username:
            raise RuntimeError("Uživatel (login) není nastaven.")

        client = _imap_connect(cfg)
        try:
            steps.append(f"Přihlašuji uživatele {cfg.username}...")
            client.login(cfg.username, password)
            test.connected = True
            steps.append("Přihlášeno k IMAP.")
            test = _process_history(client, db, cfg, days_back=30, steps=steps)
            if test.found:
                st.last_success_at = datetime.now()
        finally:
            try:
                client.logout()
            except Exception:
                pass

    except Exception as e:
        st.last_error = f"{type(e).__name__}: {e}"
        test.errors.append(st.last_error)
        if not test.message:
            test.message = st.last_error
        steps.append(st.last_error)

    db.add(st)
    db.commit()

    diag = {
        "last_attempt_at_human": _human(st.last_attempt_at),
        "last_success_at_human": _human(st.last_success_at),
        "last_error": st.last_error,
    }

    payload = {
        "ok": test.connected and (not test.errors),
        "connected": test.connected,
        "found": test.found,
        "message": test.message,
        "attachments": test.attachments,
        "processed_days": test.processed_days,
        "errors": test.errors,
        "steps": steps,
        "error": st.last_error,
    }
    return JSONResponse(payload)
