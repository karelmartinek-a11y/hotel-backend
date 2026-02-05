from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from PIL import Image, UnidentifiedImageError

from app.config import settings as app_settings


@dataclass(frozen=True)
class StoredPictogram:
    ingredient_id: int
    original_relpath: str
    thumb_relpath: str
    original_abspath: str
    thumb_abspath: str
    bytes: int
    width: int
    height: int


class InventoryMediaError(RuntimeError):
    pass


class InventoryMediaStorage:
    """Disk storage for inventory ingredient pictograms.

    Layout:
      {MEDIA_ROOT}/inventory/ingredients/{ingredient_id}/
        pictogram.jpg
        thumb.jpg
    """

    def __init__(
        self,
        media_root: str,
        *,
        max_original_px: int = 768,
        jpeg_quality: int = 85,
        thumb_px: int = 160,
        thumb_quality: int = 75,
    ) -> None:
        self.media_root = Path(media_root).resolve()
        self.max_original_px = int(max_original_px)
        self.jpeg_quality = int(jpeg_quality)
        self.thumb_px = int(thumb_px)
        self.thumb_quality = int(thumb_quality)

        if self.media_root == Path("/"):
            raise InventoryMediaError("Refusing to use '/' as media_root")
        self.media_root.mkdir(parents=True, exist_ok=True)

    def _ensure_within_root(self, p: Path) -> None:
        try:
            p.relative_to(self.media_root)
        except ValueError as e:
            raise InventoryMediaError("Path escapes media_root") from e

    def _mkdirs(self, p: Path) -> None:
        self._ensure_within_root(p)
        p.mkdir(parents=True, exist_ok=True)

    def _safe_unlink(self, p: Path) -> None:
        self._ensure_within_root(p)
        if p.exists():
            p.unlink()

    def _open_and_normalize(self, src_path: Path) -> Image.Image:
        try:
            img: Image.Image = Image.open(str(src_path))
            img.load()
        except UnidentifiedImageError as e:
            raise InventoryMediaError("Unsupported image format") from e
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        elif img.mode == "L":
            img = img.convert("RGB")
        return img

    def _resize_inplace(self, img: Image.Image, max_px: int) -> Image.Image:
        w, h = img.size
        if w <= max_px and h <= max_px:
            return img
        img.thumbnail((max_px, max_px), Image.Resampling.LANCZOS)
        return img

    def store_pictogram(
        self,
        *,
        ingredient_id: int,
        src_file: BinaryIO,
        src_filename: str = "upload",
    ) -> StoredPictogram:
        ing_id = int(ingredient_id)

        base_dir = (self.media_root / "inventory" / "ingredients" / str(ing_id)).resolve()
        tmp_dir = (self.media_root / ".tmp").resolve()
        self._mkdirs(base_dir)
        self._mkdirs(tmp_dir)

        tmp_name = (
            f"inv_{ing_id}_{os.getpid()}_"
            f"{hashlib.sha256(src_filename.encode('utf-8','ignore')).hexdigest()[:10]}.bin"
        )
        tmp_path = (tmp_dir / tmp_name).resolve()
        self._ensure_within_root(tmp_path)

        orig_rel = f"inventory/ingredients/{ing_id}/pictogram.jpg"
        thumb_rel = f"inventory/ingredients/{ing_id}/thumb.jpg"
        orig_path = (self.media_root / orig_rel).resolve()
        thumb_path = (self.media_root / thumb_rel).resolve()
        self._ensure_within_root(orig_path)
        self._ensure_within_root(thumb_path)

        try:
            with tmp_path.open("wb") as out:
                shutil.copyfileobj(src_file, out, length=1024 * 1024)
        except Exception as e:
            self._safe_unlink(tmp_path)
            raise InventoryMediaError("Failed to write temp upload") from e

        try:
            img = self._open_and_normalize(tmp_path)
        except Exception:
            self._safe_unlink(tmp_path)
            raise

        try:
            img_o = self._resize_inplace(img.copy(), self.max_original_px)
            img_o.save(
                str(orig_path),
                format="JPEG",
                quality=self.jpeg_quality,
                optimize=True,
                progressive=True,
            )
            img_t = self._resize_inplace(img.copy(), self.thumb_px)
            img_t.save(
                str(thumb_path),
                format="JPEG",
                quality=self.thumb_quality,
                optimize=True,
                progressive=True,
            )
        except Exception as e:
            self._safe_unlink(tmp_path)
            self._safe_unlink(orig_path)
            self._safe_unlink(thumb_path)
            raise InventoryMediaError("Failed to save pictogram") from e
        finally:
            self._safe_unlink(tmp_path)

        st = orig_path.stat()
        w, h = Image.open(str(orig_path)).size
        return StoredPictogram(
            ingredient_id=ing_id,
            original_relpath=orig_rel,
            thumb_relpath=thumb_rel,
            original_abspath=str(orig_path),
            thumb_abspath=str(thumb_path),
            bytes=int(st.st_size),
            width=int(w),
            height=int(h),
        )


def get_inventory_media_root(*, settings=app_settings) -> Path:
    return Path(getattr(settings, "media_root", getattr(settings, "MEDIA_ROOT", "/var/lib/hotelapp/media")))
