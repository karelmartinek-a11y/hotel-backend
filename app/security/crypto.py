from __future__ import annotations

import base64
import hashlib
from typing import cast
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken


@dataclass(frozen=True)
class Crypto:
    fernet: Fernet

    @staticmethod
    def from_secret(secret: str) -> Crypto:
        """Create Fernet instance from arbitrary secret (hashed to 32-byte key)."""
        if not secret or len(secret) < 16:
            raise ValueError("CRYPTO_SECRET je prázdné nebo příliš krátké (min 16 znaků).")
        digest = hashlib.sha256(secret.encode("utf-8")).digest()
        key = base64.urlsafe_b64encode(digest)
        return Crypto(fernet=Fernet(key))

    def encrypt_str(self, value: str) -> str:
        token = cast(bytes, self.fernet.encrypt(value.encode("utf-8")))
        return token.decode("utf-8")

    def decrypt_str(self, token: str) -> str:
        try:
            raw = cast(bytes, self.fernet.decrypt(token.encode("utf-8")))
        except InvalidToken as e:
            raise ValueError("Neplatný šifrovaný řetězec (CRYPTO_SECRET nesouhlasí nebo data jsou poškozena).") from e
        return raw.decode("utf-8")
