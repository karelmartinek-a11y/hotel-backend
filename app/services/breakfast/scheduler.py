from __future__ import annotations

import asyncio
import logging
from datetime import datetime, time, timedelta

from app.db.session import SessionLocal
from app.services.breakfast.mail_fetcher import BreakfastMailFetcher, _load_effective_config

log = logging.getLogger("hotel.breakfast.scheduler")


def _parse_hhmm(s: str) -> time:
    hh, mm = s.strip().split(":")
    return time(int(hh), int(mm))


def _now_local() -> datetime:
    # Server is expected to run in local timezone (Ubuntu + systemd). We keep it simple.
    return datetime.now()


def _compute_window(cfg_start: time, cfg_end: time, now: datetime) -> tuple[datetime, datetime]:
    start_dt = datetime.combine(now.date(), cfg_start)
    end_dt = datetime.combine(now.date(), cfg_end)
    if end_dt <= start_dt:
        # Not expected (02:00–03:00), but avoid breaking if misconfigured.
        end_dt = end_dt + timedelta(days=1)
    return start_dt, end_dt


async def breakfast_fetch_loop() -> None:
    """
    Runs forever:
      - waits until configured window start
      - within window tries to fetch breakfast for 'today'
      - on failure retries every retry_minutes until window end

    If already fetched for day D (DB row exists), it sleeps until the next day window.
    """
    fetcher = BreakfastMailFetcher()

    while True:
        try:
            # Read effective config (DB overrides env defaults).
            db = SessionLocal()
            try:
                cfg = _load_effective_config(db)
            finally:
                db.close()

            if not cfg.enabled:
                await asyncio.sleep(60)
                continue

            now = _now_local()
            start_t = _parse_hhmm(cfg.window_start_hhmm)
            end_t = _parse_hhmm(cfg.window_end_hhmm)
            win_start, win_end = _compute_window(start_t, end_t, now)

            if now < win_start:
                sleep_s = max(1, int((win_start - now).total_seconds()))
                await asyncio.sleep(sleep_s)
                continue

            if now >= win_end:
                # Window is over; sleep to next day's window start.
                next_start = win_start + timedelta(days=1)
                sleep_s = max(1, int((next_start - now).total_seconds()))
                await asyncio.sleep(sleep_s)
                continue

            # We are inside window; try to fetch for today's date.
            target = now.date()
            ok = await asyncio.to_thread(fetcher.fetch_and_store_for_day, target)
            if ok:
                # Done for today; sleep until end of window (then loop will schedule next day).
                now2 = _now_local()
                sleep_s = max(5, int((win_end - now2).total_seconds()))
                await asyncio.sleep(sleep_s)
            else:
                # Retry after configured interval (default 5 minutes), but never beyond window end.
                retry_s = max(30, int(cfg.retry_minutes) * 60)
                now2 = _now_local()
                # If we'd overshoot, wake at end to transition to next-day scheduling.
                remaining = int((win_end - now2).total_seconds())
                await asyncio.sleep(max(5, min(retry_s, max(5, remaining))))
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Breakfast scheduler loop error.")
            await asyncio.sleep(30)
