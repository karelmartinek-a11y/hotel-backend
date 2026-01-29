from __future__ import annotations

import io
from dataclasses import dataclass

from PIL import Image, ImageOps


@dataclass(frozen=True)
class ThumbnailSpec:
    """Deterministická specifikace thumbnailu.

    - Preferujeme 'contain' (thumbnail) místo 'crop', aby se neztrácel obsah.
    - JPEG output pro dobrý poměr velikost/kvalita.
    """

    max_size: tuple[int, int] = (640, 640)
    format: str = "JPEG"
    quality: int = 82
    progressive: bool = True
    optimize: bool = True


class ThumbnailError(RuntimeError):
    pass


def _safe_open_image(raw: bytes) -> Image.Image:
    """Bezpečné otevření obrázku.

    Pozn.: Pillow má ochrany proti decompression bomb, nicméně stále držíme
    vstupní velikosti/limity jinde (upload limity). Tady děláme základní sanity.
    """

    if not raw:
        raise ThumbnailError("empty image")

    # Image.open je lazy; load() vynutí dekódování.
    try:
        im = Image.open(io.BytesIO(raw))
        im.load()
    except Exception as e:  # noqa: BLE001
        raise ThumbnailError(f"invalid image: {e}") from e

    # Normalizace rotace dle EXIF.
    try:
        im = ImageOps.exif_transpose(im)
    except Exception:
        # Pokud exif_transpose selže, pokračujeme bez něj.
        pass

    return im


def _to_rgb(im: Image.Image) -> Image.Image:
    """Převod do RGB (JPEG nepodporuje alpha)."""

    if im.mode in ("RGB", "L"):
        return im.convert("RGB")

    if im.mode in ("RGBA", "LA"):
        # Kompozice na bílé pozadí (admin UI je tmavé, ale thumbnail v tabulkách
        # typicky sedí na neutrální surface; bílé pozadí je nejbezpečnější).
        bg = Image.new("RGB", im.size, (255, 255, 255))
        bg.paste(im, mask=im.split()[-1])
        return bg

    return im.convert("RGB")


def make_thumbnail_bytes(
    raw: bytes,
    *,
    spec: ThumbnailSpec | None = None,
) -> bytes:
    """Vytvoří thumbnail (bytes) z původního obrázku.

    Deterministicky:
    - EXIF transpose
    - convert to RGB
    - contain do max_size
    - uložit jako JPEG se stabilními parametry

    Vyhazuje ThumbnailError při chybě.
    """

    spec = spec or ThumbnailSpec()
    im = _safe_open_image(raw)
    im = _to_rgb(im)

    # 'thumbnail' upravuje in-place a zachová poměr stran.
    try:
        im.thumbnail(spec.max_size, Image.Resampling.LANCZOS)
    except Exception as e:  # noqa: BLE001
        raise ThumbnailError(f"thumbnail resize failed: {e}") from e

    out = io.BytesIO()

    save_kwargs = {
        "format": spec.format,
        "quality": spec.quality,
        "progressive": spec.progressive,
        "optimize": spec.optimize,
    }

    # Pillow může do JPEG vložit EXIF; chceme thumbnail bez EXIF.
    try:
        im.save(out, **save_kwargs)
    except Exception as e:  # noqa: BLE001
        raise ThumbnailError(f"thumbnail save failed: {e}") from e

    return out.getvalue()


def sniff_image_size(raw: bytes) -> tuple[int, int] | None:
    """Vrátí (w,h) pokud lze bezpečně načíst, jinak None.

    Použití: logging/telemetrie/validace (bez leakování obsahu).
    """

    try:
        im = _safe_open_image(raw)
        return im.size
    except Exception:
        return None
