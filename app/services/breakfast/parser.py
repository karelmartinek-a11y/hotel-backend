from __future__ import annotations

import re
import unicodedata
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime
from io import BytesIO

from pypdf import PdfReader


@dataclass(frozen=True)
class BreakfastRow:
    day: date
    room: str
    breakfast_count: int
    guest_name: str | None = None


DATE_RE = re.compile(
    r"(?:Přehled|Prehled)\s+stravy(?:\s+na\s+den)?\s+(\d{1,2}[./-]\d{1,2}[./-]\d{4})",
    re.IGNORECASE,
)
DATE_FALLBACK_RE = re.compile(r"\b(\d{1,2}[./-]\d{1,2}[./-]\d{4})\b")
ROOM_PREFIXES = {"KOMFORT", "LOWCOST", "SUPERIOR"}
BOOKING_NOISE = re.compile(r"(booking\.com|b\.v\.|mevris)", re.IGNORECASE)


def _strip_accents(text: str) -> str:
    base = unicodedata.normalize("NFKD", text or "")
    return "".join(ch for ch in base if not unicodedata.combining(ch))


def _parse_date_candidate(text: str) -> date:
    for fmt in ("%d.%m.%Y", "%d-%m-%Y", "%d/%m/%Y"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    raise ValueError(f"Unsupported date format: {text}")


def _find_report_date(full_text: str) -> date:
    m = DATE_RE.search(full_text)
    if m:
        return _parse_date_candidate(m.group(1))

    normalized = _strip_accents(full_text)
    m = DATE_RE.search(normalized)
    if m:
        return _parse_date_candidate(m.group(1))

    lines = full_text.splitlines()
    lines_norm = _strip_accents(full_text).splitlines()
    for idx, (_line, line_norm) in enumerate(zip(lines, lines_norm, strict=False)):
        if "prehled stravy" in line_norm.lower():
            for j in (idx, idx + 1):
                if j >= len(lines):
                    continue
                m2 = DATE_FALLBACK_RE.search(lines[j])
                if m2:
                    return _parse_date_candidate(m2.group(1))

    # Fallback: try date in the first 20 lines
    head = "\n".join(lines[:20])
    m3 = DATE_FALLBACK_RE.search(head)
    if m3:
        return _parse_date_candidate(m3.group(1))

    raise ValueError("PDF date not found (expected 'Přehled stravy <datum>').")


def _extract_guest_name(raw: str) -> str:
    """
    Extract guest name(s) from the segment before the date/fraction columns.
    - Strip room category prefixes (KOMFORT/LOWCOST/SUPERIOR)
    - Stop at the first date fragment (e.g. 24.01.-25.01.)
    - Prefer the first non-booking/non-noise token separated by ';' or '|'
    """
    if not raw:
        return ""

    head = re.split(r"\d{1,2}[./-]\d{1,2}[./-]\d{2,4}", raw, maxsplit=1)[0]
    head = head.replace("|", ";")
    candidates: list[str] = []
    for part in head.split(";"):
        cand = part.strip(" ,;-|.")
        if not cand:
            continue
        tokens = cand.split()
        while tokens and tokens[0].upper() in ROOM_PREFIXES:
            tokens = tokens[1:]
        cand = re.sub(r"\s+", " ", " ".join(tokens)).strip(" ,;-|.")
        if cand:
            candidates.append(cand)

    if not candidates:
        return ""

    for cand in candidates:
        if not BOOKING_NOISE.search(cand):
            return cand
    return candidates[0]


def parse_breakfast_pdf(pdf_bytes: bytes) -> tuple[date, list[BreakfastRow]]:
    """
    Parse Better Hotel 'Přehled stravy' PDF and extract {day, room, breakfast_count, guest_name}.

    Observed structure (example):
      - header contains 'Přehled stravy DD.M.RRRR'
      - rows begin with room number (e.g. 101) and later contain 'X / Y <n1> <n2> ...'

    """
    reader = PdfReader(BytesIO(pdf_bytes))
    full_text = "\n".join((p.extract_text() or "") for p in reader.pages)

    d = _find_report_date(full_text)

    # Build "blocks" per room because PDF text extraction sometimes breaks rows into multiple lines.
    blocks: list[str] = []
    cur: str | None = None
    for raw in full_text.splitlines():
        line = raw.strip()
        if not line:
            continue
        # Skip obvious headers/footers.
        if line.startswith("Powered by") or line.startswith("Přehled stravy") or line.startswith("POKOJ "):
            continue
        if re.match(r"^\d{3}\b", line):
            if cur:
                blocks.append(cur)
            cur = line
        else:
            if cur:
                cur += " " + line
    if cur:
        blocks.append(cur)

    # Aggregate breakfast per room (a room can appear multiple times due to multiple reservations).
    per_room: dict[str, int] = defaultdict(int)
    names: dict[str, str] = {}

    for b in blocks:
        rm = re.match(r"^(\d{3})\b", b)
        if not rm:
            continue
        room = rm.group(1)
        rest = b[rm.end() :].strip()

        frac = re.search(r"(\d+)\s*/\s*(\d+)", rest)
        if not frac:
            continue

        name_raw = rest[: frac.start()].strip(" -;|")
        guest_clean = _extract_guest_name(name_raw)

        numbers = [int(n) for n in re.findall(r"\d+", rest[frac.end() :])]
        if not numbers:
            continue
        # Columns after the fraction appear as: <bez_stravy> <snidane> <obed> <vecere> ...
        breakfast = numbers[1] if len(numbers) > 1 else numbers[0]
        if breakfast > 0:
            per_room[room] += breakfast
            if guest_clean and room not in names:
                names[room] = guest_clean

    rows = [
        BreakfastRow(
            day=d,
            room=room,
            breakfast_count=count,
            guest_name=names.get(room),
        )
        for room, count in per_room.items()
    ]
    rows.sort(key=lambda r: int(re.sub(r"\D", "", r.room) or "0"))
    return d, rows


def format_text_summary(day: date, rows: list[BreakfastRow]) -> str:
    parts = [f"Přehled snídaní na den {day.strftime('%d.%m.%Y')}"]
    for r in rows:
        parts.append(f"Pokoj {r.room}, {r.breakfast_count} osob")
    return ", ".join(parts)
