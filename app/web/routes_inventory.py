# ruff: noqa: B008
from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.db.models import (
    InventoryIngredient,
    InventoryUnit,
    StockCard,
    StockCardLine,
    StockCardType,
)
from app.db.session import get_db
from app.db.models import Base
from app.media.inventory_storage import InventoryMediaStorage, get_inventory_media_root
from app.security.admin_auth import admin_require, admin_session_is_authenticated
from app.security.csrf import csrf_protect
from app.web.routes import _base_ctx


router = APIRouter()
templates = Jinja2Templates(directory="app/web/templates")


def _unit_base_label(unit: InventoryUnit) -> str:
    # Internal base units used for storage_qty_base / qty_delta_base
    if unit == InventoryUnit.KG:
        return "g"
    if unit == InventoryUnit.L:
        return "ml"
    return unit.value


def _format_stock(qty_base: int, unit: InventoryUnit) -> str:
    qty_base = int(qty_base or 0)
    if unit == InventoryUnit.KG:
        return f"{qty_base / 1000:.3f} {unit.value}".rstrip("0").rstrip(".")
    if unit == InventoryUnit.L:
        return f"{qty_base / 1000:.3f} {unit.value}".rstrip("0").rstrip(".")
    return f"{qty_base} {unit.value}"


@router.get("/admin/inventory", response_class=HTMLResponse)
def admin_inventory_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    if not admin_session_is_authenticated(request):
        return RedirectResponse("/admin/login", status_code=303)

    def _load() -> tuple[list[InventoryIngredient], list[StockCard]]:
        ings = (
            db.execute(select(InventoryIngredient).order_by(InventoryIngredient.name.asc()))
            .scalars()
            .all()
        )
        cs = (
            db.execute(select(StockCard).order_by(StockCard.card_date.desc(), StockCard.id.desc()).limit(25))
            .scalars()
            .all()
        )
        return ings, cs

    try:
        ingredients, cards = _load()
    except Exception as exc:  # pragma: no cover
        orig = getattr(exc, "orig", exc)
        if "does not exist" in str(orig).lower() or "no such table" in str(orig).lower():
            Base.metadata.create_all(bind=db.get_bind(), checkfirst=True)
            ingredients, cards = _load()
        else:
            raise

    def _card_to_view(c: StockCard) -> dict[str, Any]:
        return {
            "id": c.id,
            "type": c.card_type.value,
            "number": c.number,
            "date": c.card_date,
            "lines": [
                {
                    "ingredient": ln.ingredient.name if ln.ingredient else "(smazáno)",
                    "qty": ln.qty_delta_base,
                }
                for ln in (c.lines or [])
            ],
        }

    return templates.TemplateResponse(
        "admin_inventory.html",
        {
            **_base_ctx(request, settings=settings, active_nav="inventory", show_splash=True, hide_shell=True),
            "ingredients": ingredients,
            "cards": [_card_to_view(c) for c in cards],
            "units": [u.value for u in InventoryUnit],
            "today_iso": date.today().isoformat(),
            "format_stock": _format_stock,
            "unit_base_label": _unit_base_label,
        },
    )


@router.post("/admin/inventory/ingredient/create")
def admin_inventory_ingredient_create(
    request: Request,
    name: str = Form(...),
    unit: str = Form(...),
    amount_per_piece_base: int = Form(0),
    db: Session = Depends(get_db),
):
    admin_require(request)
    csrf_protect(request)

    try:
        unit_e = InventoryUnit(unit)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid unit")

    ing = InventoryIngredient(
        name=(name or "").strip(),
        unit=unit_e,
        amount_per_piece_base=max(0, int(amount_per_piece_base or 0)),
    )
    if not ing.name:
        raise HTTPException(status_code=400, detail="Name required")

    db.add(ing)
    db.commit()
    return RedirectResponse("/admin/inventory", status_code=303)


@router.post("/admin/inventory/ingredient/{ingredient_id}/update")
def admin_inventory_ingredient_update(
    request: Request,
    ingredient_id: int,
    name: str = Form(...),
    unit: str = Form(...),
    amount_per_piece_base: int = Form(0),
    db: Session = Depends(get_db),
):
    admin_require(request)
    csrf_protect(request)

    ing = db.get(InventoryIngredient, int(ingredient_id))
    if not ing:
        raise HTTPException(status_code=404, detail="Not found")

    try:
        unit_e = InventoryUnit(unit)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid unit")

    ing.name = (name or "").strip()
    ing.unit = unit_e
    ing.amount_per_piece_base = max(0, int(amount_per_piece_base or 0))
    db.add(ing)
    db.commit()
    return RedirectResponse("/admin/inventory", status_code=303)


@router.post("/admin/inventory/ingredient/{ingredient_id}/delete")
def admin_inventory_ingredient_delete(
    request: Request,
    ingredient_id: int,
    db: Session = Depends(get_db),
):
    admin_require(request)
    csrf_protect(request)

    ing = db.get(InventoryIngredient, int(ingredient_id))
    if not ing:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(ing)
    db.commit()
    return RedirectResponse("/admin/inventory", status_code=303)


@router.post("/admin/inventory/ingredient/{ingredient_id}/pictogram")
def admin_inventory_ingredient_pictogram_upload(
    request: Request,
    ingredient_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    admin_require(request)
    csrf_protect(request)

    ing = db.get(InventoryIngredient, int(ingredient_id))
    if not ing:
        raise HTTPException(status_code=404, detail="Not found")

    storage = InventoryMediaStorage(settings.media_root)
    stored = storage.store_pictogram(
        ingredient_id=ing.id,
        src_file=file.file,
        src_filename=file.filename or "upload",
    )
    ing.pictogram_path = stored.original_relpath
    ing.pictogram_thumb_path = stored.thumb_relpath
    db.add(ing)
    db.commit()
    return RedirectResponse("/admin/inventory", status_code=303)


@router.get("/admin/inventory/media/{ingredient_id}/{kind}")
def admin_inventory_media(
    request: Request,
    ingredient_id: int,
    kind: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    admin_require(request)
    if kind not in {"thumb", "original"}:
        raise HTTPException(status_code=400, detail="Invalid kind")
    ing = db.get(InventoryIngredient, int(ingredient_id))
    if not ing:
        raise HTTPException(status_code=404, detail="Not found")

    rel = ing.pictogram_thumb_path if kind == "thumb" else ing.pictogram_path
    if not rel:
        raise HTTPException(status_code=404, detail="Missing")

    root = get_inventory_media_root(settings=settings)
    p = (root / rel).resolve()
    try:
        p.relative_to(root.resolve())
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid path")
    if not p.exists():
        raise HTTPException(status_code=404, detail="File missing")
    return FileResponse(path=p)


@router.post("/admin/inventory/cards/create")
async def admin_inventory_create_card(
    request: Request,
    card_type: str = Form(...),
    number: str = Form(...),
    card_date: str = Form(...),
    db: Session = Depends(get_db),
):
    admin_require(request)
    csrf_protect(request)

    try:
        ct = StockCardType(card_type)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid card type")

    try:
        d = date.fromisoformat(card_date)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid date")

    form = await request.form()
    ingredient_ids = form.getlist("ingredient_id")
    qty_bases = form.getlist("qty_base")

    pairs: list[tuple[int, int]] = []
    for i, q in zip(ingredient_ids, qty_bases, strict=False):
        try:
            ing_id = int(i)
            qty = int(q)
        except Exception:
            continue
        if ing_id <= 0 or qty <= 0:
            continue
        pairs.append((ing_id, qty))

    if not pairs:
        raise HTTPException(status_code=400, detail="Card must contain at least one line")

    card = StockCard(card_type=ct, number=(number or "").strip(), card_date=d)
    if not card.number:
        raise HTTPException(status_code=400, detail="Card number required")

    db.add(card)
    db.flush()  # assign id

    for ing_id, qty in pairs:
        ing = db.get(InventoryIngredient, ing_id)
        if not ing:
            continue
        delta = qty if ct == StockCardType.IN else -qty
        ln = StockCardLine(card_id=card.id, ingredient_id=ing.id, qty_delta_base=delta)
        db.add(ln)
        ing.stock_qty_base = int(ing.stock_qty_base or 0) + int(delta)
        db.add(ing)

    db.commit()
    return RedirectResponse("/admin/inventory", status_code=303)
