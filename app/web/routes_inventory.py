from __future__ import annotations

import shutil
from collections import defaultdict
from datetime import date
import json
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload

from app.config import Settings
from app.db.models import (
    InventoryIngredient,
    InventoryUnit,
    StockCard,
    StockCardLine,
    StockCardType,
)
from app.db.session import get_db
from app.media.inventory_storage import (
    InventoryMediaError,
    InventoryMediaStorage,
    get_inventory_media_root,
)
from app.security.admin_auth import AdminAuthError, admin_require, admin_session_is_authenticated
from app.security.csrf import csrf_protect, csrf_token_ensure
from .routes import _base_ctx, _redirect

router = APIRouter()
templates = Jinja2Templates(directory="app/web/templates")


def _parse_unit(raw: str) -> InventoryUnit:
    try:
        return InventoryUnit(raw)
    except Exception:
        return InventoryUnit.G


def _parse_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def unit_base_label(unit: InventoryUnit) -> str:
    if unit in (InventoryUnit.KG, InventoryUnit.G):
        return "g"
    if unit in (InventoryUnit.L, InventoryUnit.ML):
        return "ml"
    return "ks"


def _format_qty_base(qty: int, unit: InventoryUnit) -> str:
    base = unit_base_label(unit)
    if base == "g":
        if abs(qty) >= 1000:
            return f"{qty / 1000:.2f} kg"
        return f"{qty} g"
    if base == "ml":
        if abs(qty) >= 1000:
            return f"{qty / 1000:.2f} l"
        return f"{qty} ml"
    return f"{qty} ks"


def format_stock(qty_base: int, unit: InventoryUnit) -> str:
    return _format_qty_base(int(qty_base or 0), unit)


def _serialize_card(card: StockCard) -> dict[str, Any]:
    lines: list[dict[str, Any]] = []
    for ln in card.lines or []:
        ing_name = ln.ingredient.name if ln.ingredient else "?"
        unit = ln.ingredient.unit if ln.ingredient else InventoryUnit.G
        qty_pieces = int(ln.qty_pieces or 0)
        if qty_pieces == 0:
            per_piece = Decimal(ln.ingredient.amount_per_piece_base or 0) if ln.ingredient else Decimal(0)
            if per_piece > 0:
                qty_pieces = int(
                    (Decimal(ln.qty_delta_base) / per_piece).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
                )
            else:
                qty_pieces = int(ln.qty_delta_base)
        lines.append({
            "ingredient_id": ln.ingredient_id,
            "ingredient": ing_name,
            "qty": _format_qty_base(ln.qty_delta_base, unit),
            "qty_pieces": abs(int(qty_pieces)),
        })

    return {
        "id": card.id,
        "type": card.card_type.value if isinstance(card.card_type, StockCardType) else str(card.card_type),
        "number": card.number,
        "date": card.card_date.isoformat(),
        "lines": lines,
    }


def _parse_decimal(value: Any) -> Decimal:
    try:
        text = str(value).strip()
        if not text:
            return Decimal("0")
        return Decimal(text)
    except (InvalidOperation, TypeError, ValueError):
        return Decimal("0")


def _recalculate_ingredient_stock(db: Session, ing: InventoryIngredient) -> None:
    per_piece = int(ing.amount_per_piece_base or 0)
    total = 0
    lines = db.scalars(
        select(StockCardLine).where(StockCardLine.ingredient_id == ing.id).order_by(StockCardLine.id.asc())
    ).all()
    for ln in lines:
        qty_pieces = int(ln.qty_pieces or 0)
        if qty_pieces == 0 and ln.qty_delta_base:
            if per_piece > 0:
                qty_pieces = int(
                    (Decimal(ln.qty_delta_base) / Decimal(per_piece)).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
                )
            else:
                qty_pieces = int(ln.qty_delta_base)
            ln.qty_pieces = qty_pieces

        if per_piece > 0:
            ln.qty_delta_base = int(qty_pieces * per_piece)
        else:
            ln.qty_delta_base = int(qty_pieces)
        total += ln.qty_delta_base
        db.add(ln)
    ing.stock_qty_base = int(total)
    db.add(ing)


def _store_pictogram_for_ingredient(ing: InventoryIngredient, upload_file: UploadFile | None) -> None:
    if not upload_file or not (upload_file.filename or "").strip():
        return
    storage = InventoryMediaStorage(str(get_inventory_media_root()))
    stored = storage.store_pictogram(
        ingredient_id=ing.id,
        src_file=upload_file.file,
        src_filename=upload_file.filename or "upload",
    )
    ing.pictogram_path = stored.original_relpath
    ing.pictogram_thumb_path = stored.thumb_relpath


def _generate_out_card_number(db: Session, card_date: date) -> str:
    prefix = f"V{card_date.strftime('%y%m%d')}"
    total = db.scalar(
        select(func.count()).where(StockCard.card_type == StockCardType.OUT)
    )
    seq = int(total or 0) + 1
    return f"{prefix}-{seq:04d}"


@router.get("/admin/inventory", response_class=HTMLResponse)
def admin_inventory(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    return _redirect("/admin/inventory/ingredients")


@router.get("/admin/inventory/ingredients", response_class=HTMLResponse)
def admin_inventory_ingredients(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    if not admin_session_is_authenticated(request):
        return _redirect("/admin/login")

    ingredients = db.scalars(
        select(InventoryIngredient).order_by(InventoryIngredient.name.asc())
    ).all()

    ctx = {
        **_base_ctx(request, settings=settings, active_nav="inventory"),
        "inventory_section": "ingredients",
        "ingredients": ingredients,
        "units": [u.value for u in InventoryUnit],
        "unit_base_label": unit_base_label,
        "format_stock": format_stock,
        "csrf_token": csrf_token_ensure(request),
        "inventory_base_path": "/admin/inventory",
        "inventory_media_base": "/admin/inventory/media",
        "readonly": False,
        "show_admin_sidebar": True,
        "back_url": None,
    }
    return templates.TemplateResponse("admin_inventory_ingredients.html", ctx)


@router.get("/admin/inventory/stock", response_class=HTMLResponse)
def admin_inventory_stock(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    if not admin_session_is_authenticated(request):
        return _redirect("/admin/login")

    ingredients = db.scalars(
        select(InventoryIngredient).order_by(InventoryIngredient.name.asc())
    ).all()

    inventory_summary = [
        {
            "id": ing.id,
            "name": ing.name,
            "stock_text": format_stock(ing.stock_qty_base or 0, ing.unit),
            "base_qty": ing.stock_qty_base or 0,
            "unit_label": unit_base_label(ing.unit),
            "per_piece": ing.amount_per_piece_base or 0,
            "unit": ing.unit.value,
        }
        for ing in ingredients
    ]

    ctx = {
        **_base_ctx(request, settings=settings, active_nav="inventory"),
        "inventory_section": "stock",
        "inventory_summary": inventory_summary,
        "csrf_token": csrf_token_ensure(request),
        "inventory_base_path": "/admin/inventory",
        "readonly": False,
        "show_admin_sidebar": True,
        "back_url": None,
    }
    return templates.TemplateResponse("admin_inventory_stock.html", ctx)


@router.get("/admin/inventory/movements", response_class=HTMLResponse)
def admin_inventory_movements(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    if not admin_session_is_authenticated(request):
        return _redirect("/admin/login")

    ingredients = db.scalars(
        select(InventoryIngredient).order_by(InventoryIngredient.name.asc())
    ).all()

    cards = db.scalars(
        select(StockCard)
        .options(selectinload(StockCard.lines).selectinload(StockCardLine.ingredient))
        .order_by(StockCard.card_date.desc(), StockCard.id.desc())
        .limit(200)
    ).all()

    history_cards = db.scalars(
        select(StockCard)
        .options(selectinload(StockCard.lines).selectinload(StockCardLine.ingredient))
        .order_by(StockCard.card_date.asc(), StockCard.id.asc())
    ).all()

    running_totals: dict[int, int] = defaultdict(int)
    history_rows: list[dict[str, Any]] = []
    for card in history_cards:
        card_type_label = card.card_type.value if isinstance(card.card_type, StockCardType) else str(card.card_type)
        for ln in card.lines or []:
            ing = ln.ingredient
            ing_id = ln.ingredient_id
            unit_for_line = (ing.unit if ing else InventoryUnit.G)
            delta = ln.qty_delta_base or 0
            running_totals[ing_id] += delta
            delta_label = _format_qty_base(abs(delta), unit_for_line)
            delta_display = f"{'+' if delta >= 0 else '-'}{delta_label}"
            history_rows.append(
                {
                    "ingredient_id": ing_id,
                    "ingredient_name": ing.name if ing else "?",
                    "card_type": card_type_label,
                    "card_number": card.number,
                    "card_date": card.card_date.isoformat(),
                    "delta": delta_display,
                    "running": _format_qty_base(running_totals[ing_id], unit_for_line),
                }
            )

    cards_serialized: list[dict[str, Any]] = []
    for card in cards:
        payload = _serialize_card(card)
        payload["lines_json"] = json.dumps(payload["lines"], ensure_ascii=False)
        payload["search_text"] = (
            f"{payload['number']} {payload['date']} {payload['type']} "
            + " ".join(line["ingredient"] for line in payload["lines"])
        ).lower()
        cards_serialized.append(payload)

    ctx = {
        **_base_ctx(request, settings=settings, active_nav="inventory"),
        "inventory_section": "movements",
        "ingredients": ingredients,
        "units": [u.value for u in InventoryUnit],
        "unit_base_label": unit_base_label,
        "format_stock": format_stock,
        "today_iso": date.today().isoformat(),
        "csrf_token": csrf_token_ensure(request),
        "cards": cards_serialized,
        "history_rows": history_rows,
        "inventory_base_path": "/admin/inventory",
        "inventory_media_base": "/admin/inventory/media",
        "readonly": False,
        "allow_card_create": True,
        "allow_card_manage": True,
        "show_admin_sidebar": True,
        "back_url": None,
    }
    return templates.TemplateResponse("admin_inventory_movements.html", ctx)


@router.post("/admin/inventory/ingredient/create")
def admin_inventory_ingredient_create(
    request: Request,
    name: str = Form(""),
    unit: str = Form("g"),
    amount_per_piece_base: int = Form(0),
    pictogram: UploadFile | None = File(None),
    db: Session = Depends(get_db),
):
    try:
        admin_require(request)
        csrf_protect(request)
    except AdminAuthError:
        return _redirect("/admin/login")

    name = (name or "").strip()
    if not name:
        request.session["flash"] = {"type": "error", "message": "Název je povinný."}
        return _redirect("/admin/inventory/ingredients")

    ing = InventoryIngredient(
        name=name,
        unit=_parse_unit(unit or "g"),
        amount_per_piece_base=max(0, _parse_int(amount_per_piece_base)),
        stock_qty_base=0,
    )
    db.add(ing)
    db.flush()
    pictogram_error: str | None = None
    try:
        if pictogram and pictogram.filename:
            _store_pictogram_for_ingredient(ing, pictogram)
            db.add(ing)
    except InventoryMediaError as exc:
        pictogram_error = str(exc)
    db.commit()

    if pictogram_error:
        request.session["flash"] = {
            "type": "warning",
            "message": f"Surovina vytvořena, ale ikona nebyla uložena: {pictogram_error}",
        }
    else:
        request.session["flash"] = {"type": "success", "message": "Surovina vytvořena."}
    return _redirect("/admin/inventory/ingredients")


@router.post("/admin/inventory/ingredient/{ingredient_id}/update")
def admin_inventory_ingredient_update(
    request: Request,
    ingredient_id: int,
    name: str = Form(""),
    unit: str = Form("g"),
    amount_per_piece_base: int = Form(0),
    pictogram: UploadFile | None = File(None),
    db: Session = Depends(get_db),
):
    try:
        admin_require(request)
        csrf_protect(request)
    except AdminAuthError:
        return _redirect("/admin/login")

    ing = db.get(InventoryIngredient, int(ingredient_id))
    if not ing:
        request.session["flash"] = {"type": "error", "message": "Surovina nenalezena."}
        return _redirect("/admin/inventory/ingredients")

    ing.name = (name or ing.name).strip() or ing.name
    ing.unit = _parse_unit(unit or ing.unit.value)
    ing.amount_per_piece_base = max(0, _parse_int(amount_per_piece_base, ing.amount_per_piece_base))
    if pictogram and pictogram.filename:
        try:
            _store_pictogram_for_ingredient(ing, pictogram)
        except InventoryMediaError as exc:
            request.session["flash"] = {"type": "warning", "message": f"Změna uložena, ikona ne: {exc}"}
            _recalculate_ingredient_stock(db, ing)
            db.commit()
            return _redirect("/admin/inventory/ingredients")
    _recalculate_ingredient_stock(db, ing)
    db.commit()

    request.session["flash"] = {
        "type": "success",
        "message": "Uloženo a přepočítáno ze všech karet.",
    }
    return _redirect("/admin/inventory/ingredients")


@router.post("/admin/inventory/ingredient/{ingredient_id}/delete")
def admin_inventory_ingredient_delete(
    request: Request,
    ingredient_id: int,
    db: Session = Depends(get_db),
):
    try:
        admin_require(request)
        csrf_protect(request)
    except AdminAuthError:
        return _redirect("/admin/login")

    ing = db.get(InventoryIngredient, int(ingredient_id))
    if not ing:
        request.session["flash"] = {"type": "error", "message": "Surovina nenalezena."}
        return _redirect("/admin/inventory/ingredients")

    if ing.card_lines:
        request.session["flash"] = {
            "type": "error",
            "message": "Nelze smazat: surovina je použita na kartách.",
        }
        return _redirect("/admin/inventory/ingredients")

    media_root = get_inventory_media_root()
    try:
        db.delete(ing)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        request.session["flash"] = {"type": "error", "message": "Mazání selhalo."}
        return _redirect("/admin/inventory/ingredients")

    ing_dir = (Path(media_root) / "inventory" / "ingredients" / str(ingredient_id)).resolve()
    if ing_dir.exists():
        shutil.rmtree(ing_dir, ignore_errors=True)

    request.session["flash"] = {"type": "success", "message": "Smazáno."}
    return _redirect("/admin/inventory/ingredients")


@router.post("/admin/inventory/ingredient/{ingredient_id}/pictogram")
def admin_inventory_ingredient_pictogram(
    request: Request,
    ingredient_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    try:
        admin_require(request)
        csrf_protect(request)
    except AdminAuthError:
        return _redirect("/admin/login")

    ing = db.get(InventoryIngredient, int(ingredient_id))
    if not ing:
        request.session["flash"] = {"type": "error", "message": "Surovina nenalezena."}
        return _redirect("/admin/inventory/ingredients")

    try:
        _store_pictogram_for_ingredient(ing, file)
        db.add(ing)
        db.commit()
        request.session["flash"] = {"type": "success", "message": "Ikona nahrána."}
    except InventoryMediaError as exc:
        db.rollback()
        request.session["flash"] = {"type": "error", "message": str(exc)}
    except Exception:
        db.rollback()
        request.session["flash"] = {"type": "error", "message": "Nahrání selhalo."}

    return _redirect("/admin/inventory/ingredients")


@router.post("/admin/inventory/cards/create")
def admin_inventory_card_create(
    request: Request,
    card_type: str = Form("IN"),
    number: str = Form(""),
    card_date: str = Form(""),
    ingredient_id: list[str] = Form([]),
    qty_pieces: list[str] = Form([]),
    db: Session = Depends(get_db),
):
    try:
        admin_require(request)
        csrf_protect(request)
    except AdminAuthError:
        return _redirect("/admin/login")

    try:
        c_type = StockCardType((card_type or "IN").upper())
    except Exception:
        c_type = StockCardType.IN

    try:
        c_date = date.fromisoformat(card_date) if card_date else date.today()
    except Exception:
        c_date = date.today()

    card_number = (number or "").strip()
    if c_type == StockCardType.OUT:
        card_number = _generate_out_card_number(db, c_date)
    elif not card_number:
        request.session["flash"] = {"type": "error", "message": "Příjmová karta musí mít číslo dodacího listu."}
        return _redirect("/admin/inventory/movements")

    lines: list[tuple[InventoryIngredient, int, int]] = []
    for ing_raw, qty_raw in zip(ingredient_id or [], qty_pieces or []):
        if not ing_raw or not qty_raw:
            continue
        ing = db.get(InventoryIngredient, _parse_int(ing_raw))
        if not ing:
            continue
        qty_decimal = _parse_decimal(qty_raw)
        if qty_decimal <= 0:
            continue
        qty_int = int(qty_decimal.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        if qty_int <= 0:
            continue
        per_piece = Decimal(ing.amount_per_piece_base or 0)
        if per_piece > 0:
            total_base = Decimal(qty_int) * per_piece
        else:
            total_base = Decimal(qty_int)
        total_base = total_base.quantize(Decimal("1"), rounding=ROUND_HALF_UP)
        delta = int(total_base)
        if delta == 0:
            continue
        if c_type == StockCardType.OUT:
            delta = -delta
            qty_int = -qty_int
        lines.append((ing, delta, qty_int))

    if not lines:
        request.session["flash"] = {
            "type": "error",
            "message": "Vyplňte alespoň jednu položku s množstvím.",
        }
        return _redirect("/admin/inventory/movements")

    card = StockCard(card_type=c_type, number=card_number or "—", card_date=c_date)
    db.add(card)
    db.flush()

    try:
        for ing, delta, qty_int in lines:
            line = StockCardLine(
                card_id=card.id,
                ingredient_id=ing.id,
                qty_delta_base=delta,
                qty_pieces=qty_int,
            )
            ing.stock_qty_base = int((ing.stock_qty_base or 0) + delta)
            db.add(line)
            db.add(ing)
        db.commit()
        request.session["flash"] = {"type": "success", "message": "Karta uložena."}
    except SQLAlchemyError as exc:
        db.rollback()
        request.session["flash"] = {"type": "error", "message": f"Uložení selhalo: {exc}"}

    return _redirect("/admin/inventory/movements")


@router.post("/admin/inventory/cards/{card_id}/update")
def admin_inventory_card_update(
    request: Request,
    card_id: int,
    card_type: str = Form("IN"),
    number: str = Form(""),
    card_date: str = Form(""),
    ingredient_id: list[str] = Form([]),
    qty_pieces: list[str] = Form([]),
    db: Session = Depends(get_db),
):
    try:
        admin_require(request)
        csrf_protect(request)
    except AdminAuthError:
        return _redirect("/admin/login")

    card = db.get(StockCard, int(card_id))
    if not card:
        request.session["flash"] = {"type": "error", "message": "Karta nenalezena."}
        return _redirect("/admin/inventory/movements")

    try:
        c_type = StockCardType((card_type or card.card_type.value).upper())
    except Exception:
        c_type = card.card_type

    try:
        c_date = date.fromisoformat(card_date) if card_date else card.card_date
    except Exception:
        c_date = card.card_date

    card_number = (number or "").strip()
    if c_type == StockCardType.OUT:
        if card.card_type == StockCardType.OUT and card.number:
            card_number = card.number
        else:
            card_number = _generate_out_card_number(db, c_date)
    elif not card_number:
        request.session["flash"] = {"type": "error", "message": "Příjmová karta musí mít číslo."}
        return _redirect("/admin/inventory/movements")

    lines: list[tuple[InventoryIngredient, int, int]] = []
    for ing_raw, qty_raw in zip(ingredient_id or [], qty_pieces or []):
        if not ing_raw or not qty_raw:
            continue
        ing = db.get(InventoryIngredient, _parse_int(ing_raw))
        if not ing:
            continue
        qty_decimal = _parse_decimal(qty_raw)
        if qty_decimal <= 0:
            continue
        qty_int = int(qty_decimal.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        if qty_int <= 0:
            continue
        per_piece = Decimal(ing.amount_per_piece_base or 0)
        if per_piece > 0:
            total_base = Decimal(qty_int) * per_piece
        else:
            total_base = Decimal(qty_int)
        total_base = total_base.quantize(Decimal("1"), rounding=ROUND_HALF_UP)
        delta = int(total_base)
        if delta == 0:
            continue
        if c_type == StockCardType.OUT:
            delta = -delta
            qty_int = -qty_int
        lines.append((ing, delta, qty_int))

    if not lines:
        request.session["flash"] = {"type": "error", "message": "Vyplňte alespoň jednu položku s množstvím."}
        return _redirect("/admin/inventory/movements")

    affected_ids = {ln.ingredient_id for ln in card.lines}
    affected_ids.update(ing.id for ing, _, _ in lines)

    try:
        for ln in list(card.lines):
            db.delete(ln)
        card.card_type = c_type
        card.number = card_number
        card.card_date = c_date
        db.add(card)
        db.flush()

        for ing, delta, qty_int in lines:
            line = StockCardLine(
                card_id=card.id,
                ingredient_id=ing.id,
                qty_delta_base=delta,
                qty_pieces=qty_int,
            )
            db.add(line)

        for ing_id in sorted(affected_ids):
            ing = db.get(InventoryIngredient, int(ing_id))
            if ing:
                _recalculate_ingredient_stock(db, ing)
        db.commit()
        request.session["flash"] = {"type": "success", "message": "Karta upravena a přepočítána."}
    except SQLAlchemyError as exc:
        db.rollback()
        request.session["flash"] = {"type": "error", "message": f"Uložení selhalo: {exc}"}

    return _redirect("/admin/inventory/movements")


@router.post("/admin/inventory/cards/{card_id}/delete")
def admin_inventory_card_delete(
    request: Request,
    card_id: int,
    db: Session = Depends(get_db),
):
    try:
        admin_require(request)
        csrf_protect(request)
    except AdminAuthError:
        return _redirect("/admin/login")

    card = db.get(StockCard, int(card_id))
    if not card:
        request.session["flash"] = {"type": "error", "message": "Karta nenalezena."}
        return _redirect("/admin/inventory/movements")

    affected_ids = {ln.ingredient_id for ln in card.lines}
    try:
        db.delete(card)
        db.flush()
        for ing_id in sorted(affected_ids):
            ing = db.get(InventoryIngredient, int(ing_id))
            if ing:
                _recalculate_ingredient_stock(db, ing)
        db.commit()
        request.session["flash"] = {"type": "success", "message": "Karta smazána a přepočítána."}
    except SQLAlchemyError as exc:
        db.rollback()
        request.session["flash"] = {"type": "error", "message": f"Mazání selhalo: {exc}"}

    return _redirect("/admin/inventory/movements")


@router.get("/admin/inventory/media/{ingredient_id}/{kind}")
def admin_inventory_media(
    request: Request,
    ingredient_id: int,
    kind: str,
    db: Session = Depends(get_db),
) -> Response:
    try:
        admin_require(request)
    except AdminAuthError:
        return _redirect("/admin/login")

    ing = db.get(InventoryIngredient, int(ingredient_id))
    if not ing:
        raise HTTPException(status_code=404)

    rel = ing.pictogram_thumb_path if kind == "thumb" else ing.pictogram_path
    if not rel:
        raise HTTPException(status_code=404)

    media_root = Path(get_inventory_media_root())
    abs_path = (media_root / rel).resolve()
    try:
        abs_path.relative_to(media_root)
    except ValueError:
        raise HTTPException(status_code=404) from None

    if not abs_path.exists():
        raise HTTPException(status_code=404)

    return FileResponse(str(abs_path), media_type="image/jpeg")
