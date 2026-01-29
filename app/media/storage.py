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
class StoredPhoto:
    report_id: int
    photo_id: int
    original_relpath: str
    thumb_relpath: str
    original_abspath: str
    thumb_abspath: str
    sha256: str
    bytes: int
    width: int
    height: int


class MediaStorageError(RuntimeError):
    pass


class MediaStorage:
    """Disk storage for HOTEL report photos.

    Requirements:
      - store originals + thumbnails on disk
      - deterministic directory structure
      - safe path handling
      - support delete of all report files

    Directory layout (deterministic):
      {MEDIA_ROOT}/reports/{report_id}/
        original/{photo_id}.jpg
        thumb/{photo_id}.jpg

    Notes:
      - We always re-encode to JPEG for consistency and to avoid serving user-supplied formats.
      - Callers must enforce authorization; this class only handles filesystem operations.
    """

    def __init__(
        self,
        media_root: str,
        *,
        max_original_px: int = 2400,
        jpeg_quality: int = 85,
        thumb_max_px: int = 480,
        thumb_quality: int = 75,
    ) -> None:
        self.media_root = Path(media_root).resolve()
        self.max_original_px = int(max_original_px)
        self.jpeg_quality = int(jpeg_quality)
        self.thumb_max_px = int(thumb_max_px)
        self.thumb_quality = int(thumb_quality)

        if self.media_root == Path("/"):
            raise MediaStorageError("Refusing to use '/' as media_root")

        self.media_root.mkdir(parents=True, exist_ok=True)

    def _report_dir(self, report_id: int) -> Path:
        # report_id is server-generated integer, safe for path composition
        return (self.media_root / "reports" / str(int(report_id))).resolve()

    def _ensure_within_root(self, p: Path) -> None:
        try:
            p.relative_to(self.media_root)
        except ValueError as e:
            raise MediaStorageError("Path escapes media_root") from e

    def _mkdirs(self, p: Path) -> None:
        self._ensure_within_root(p)
        p.mkdir(parents=True, exist_ok=True)

    def _safe_unlink(self, p: Path) -> None:
        self._ensure_within_root(p)
        if p.exists():
            p.unlink()

    def _sha256_file(self, p: Path) -> str:
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _open_and_normalize(self, src_path: Path) -> tuple[Image.Image, int, int]:
        try:
            img: Image.Image = Image.open(str(src_path))
            img.load()
        except UnidentifiedImageError as e:
            raise MediaStorageError("Unsupported image format") from e

        # Convert to RGB (drop alpha) to allow consistent JPEG output
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        elif img.mode == "L":
            img = img.convert("RGB")

        w, h = img.size
        return img, int(w), int(h)

    def _resize_inplace(self, img: Image.Image, max_px: int) -> Image.Image:
        max_px = int(max_px)
        if max_px <= 0:
            return img
        w, h = img.size
        if w <= max_px and h <= max_px:
            return img
        img.thumbnail((max_px, max_px), Image.Resampling.LANCZOS)
        return img

    def store_photo(
        self,
        *,
        report_id: int,
        photo_id: int,
        src_file: BinaryIO,
        src_filename: str = "upload",
    ) -> StoredPhoto:
        """Store uploaded image.

        - Reads uploaded file into a temporary file inside media_root/.tmp to avoid cross-device moves.
        - Decodes with Pillow and re-encodes as JPEG.
        - Generates thumbnail.

        Caller should wrap DB transaction around this and clean up on failure.
        """

        report_id_i = int(report_id)
        photo_id_i = int(photo_id)

        base_dir = self._report_dir(report_id_i)
        orig_dir = (base_dir / "original").resolve()
        thumb_dir = (base_dir / "thumb").resolve()
        tmp_dir = (self.media_root / ".tmp").resolve()

        self._mkdirs(orig_dir)
        self._mkdirs(thumb_dir)
        self._mkdirs(tmp_dir)

        # Temp upload path
        tmp_name = f"r{report_id_i}_p{photo_id_i}_{os.getpid()}_{hashlib.sha256(src_filename.encode('utf-8','ignore')).hexdigest()[:10]}.bin"
        tmp_path = (tmp_dir / tmp_name).resolve()
        self._ensure_within_root(tmp_path)

        # Final paths (always .jpg)
        orig_rel = f"reports/{report_id_i}/original/{photo_id_i}.jpg"
        thumb_rel = f"reports/{report_id_i}/thumb/{photo_id_i}.jpg"
        orig_path = (self.media_root / orig_rel).resolve()
        thumb_path = (self.media_root / thumb_rel).resolve()
        self._ensure_within_root(orig_path)
        self._ensure_within_root(thumb_path)

        # Write upload to temp file
        try:
            with tmp_path.open("wb") as out:
                shutil.copyfileobj(src_file, out, length=1024 * 1024)
        except Exception as e:
            self._safe_unlink(tmp_path)
            raise MediaStorageError("Failed to write temp upload") from e

        # Decode and normalize
        try:
            img, w0, h0 = self._open_and_normalize(tmp_path)
        except Exception:
            self._safe_unlink(tmp_path)
            raise

        # Resize and save original
        try:
            img_orig = self._resize_inplace(img.copy(), self.max_original_px)
            img_orig.save(str(orig_path), format="JPEG", quality=self.jpeg_quality, optimize=True, progressive=True)
        except Exception as e:
            self._safe_unlink(tmp_path)
            self._safe_unlink(orig_path)
            raise MediaStorageError("Failed to save original") from e

        # Save thumbnail
        try:
            img_thumb = self._resize_inplace(img.copy(), self.thumb_max_px)
            img_thumb.save(str(thumb_path), format="JPEG", quality=self.thumb_quality, optimize=True, progressive=True)
        except Exception as e:
            self._safe_unlink(tmp_path)
            self._safe_unlink(orig_path)
            self._safe_unlink(thumb_path)
            raise MediaStorageError("Failed to save thumbnail") from e
        finally:
            self._safe_unlink(tmp_path)

        try:
            st = orig_path.stat()
        except Exception as e:
            raise MediaStorageError("Failed to stat stored file") from e

        sha = self._sha256_file(orig_path)

        # Get final dimensions from original file we stored
        try:
            with Image.open(str(orig_path)) as im2:
                im2.load()
                w1, h1 = im2.size
        except Exception as e:
            raise MediaStorageError("Failed to read stored image") from e

        return StoredPhoto(
            report_id=report_id_i,
            photo_id=photo_id_i,
            original_relpath=orig_rel,
            thumb_relpath=thumb_rel,
            original_abspath=str(orig_path),
            thumb_abspath=str(thumb_path),
            sha256=sha,
            bytes=int(st.st_size),
            width=int(w1),
            height=int(h1),
        )

    def delete_report(self, report_id: int) -> None:
        """Delete all files for a report (originals + thumbnails).

        Must be called when admin deletes report. Safe if report directory does not exist.
        """

        report_id_i = int(report_id)
        base_dir = self._report_dir(report_id_i)
        self._ensure_within_root(base_dir)

        # Only allow deleting within {media_root}/reports/{id}
        if not str(base_dir).startswith(str((self.media_root / "reports").resolve())):
            raise MediaStorageError("Refusing to delete outside reports directory")

        if base_dir.exists():
            shutil.rmtree(base_dir)

    def open_for_read(self, relpath: str) -> Path:
        """Return absolute Path for a stored media file by relative path.

        Use this for streaming in authorized endpoints.
        """

        rel = relpath.lstrip("/")
        p = (self.media_root / rel).resolve()
        self._ensure_within_root(p)
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(relpath)
        return p


def get_media_paths_for_photo(*, settings=app_settings, photo) -> tuple[Path, Path]:
    """Return absolute (original, thumb) paths for a ReportPhoto row."""

    root = Path(getattr(settings, "media_root", getattr(settings, "MEDIA_ROOT", "/var/lib/hotelapp/media")))
    orig = root / photo.file_path
    thumb = root / photo.thumb_path
    return orig, thumb
