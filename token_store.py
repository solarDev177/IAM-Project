# Cloudflare IAM Explorer
# token store

import json
import os
from pathlib import Path
from typing import Dict, List

import keyring
from keyring.errors import KeyringError, NoKeyringError
from cryptography.fernet import Fernet, InvalidToken


class TokenStore:
    TOKEN_TYPES: List[str] = ["Account Read", "Account Edit", "Group Read", "Group Edit"]

    KEYRING_SERVICE = "cf_iam_explorer"
    KEYRING_USERNAME = "token_store_master_key"

    def __init__(self, app_folder: str = "cf_iam_explorer", filename: str = "tokens.json"):
        self.app_folder = app_folder
        self.filename = filename

    def path(self) -> Path:
        base = Path(os.getenv("APPDATA") or (Path.home() / ".config"))
        folder = base / self.app_folder
        folder.mkdir(parents=True, exist_ok=True)
        return folder / self.filename

    def _keyring_backend_name(self) -> str:
        try:
            backend = keyring.get_keyring()
            return f"{backend.__class__.__module__}.{backend.__class__.__name__}"
        except Exception:
            return "unknown"

    def _raise_keyring_unavailable(self, action: str, original_error: Exception | None = None) -> None:
        backend = self._keyring_backend_name()
        msg = (
            f"Unable to {action} because no usable system keyring backend is available.\n\n"
            f"Detected backend: {backend}\n\n"
            f"On Linux, install/configure a supported secret store such as:\n"
            f"  - GNOME Keyring / Secret Service, or\n"
            f"  - KWallet\n\n"
            f"If running headless, make sure D-Bus and the keyring service are available.\n"
            f"This app will not fall back to plaintext storage."
        )
        raise RuntimeError(msg) from original_error

    def _get_or_create_master_key(self) -> bytes:
        try:
            existing = keyring.get_password(self.KEYRING_SERVICE, self.KEYRING_USERNAME)
            if existing:
                return existing.encode("utf-8")

            key = Fernet.generate_key()  # already urlsafe base64-encoded bytes
            keyring.set_password(self.KEYRING_SERVICE, self.KEYRING_USERNAME, key.decode("utf-8"))
            return key

        except (NoKeyringError, KeyringError) as e:
            self._raise_keyring_unavailable("access the encryption key", e)
        except Exception as e:
            raise RuntimeError(f"Unexpected error while accessing the system keyring: {e}") from e

    def _fernet(self) -> Fernet:
        return Fernet(self._get_or_create_master_key())

    def load(self) -> Dict[str, str]:
        path = self.path()
        out = {k: "" for k in self.TOKEN_TYPES}

        if not path.exists():
            return out

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return out

        if not isinstance(data, dict):
            return out

        f = self._fernet()

        for k in self.TOKEN_TYPES:
            enc = data.get(k)
            if not isinstance(enc, str) or not enc.strip():
                continue

            try:
                out[k] = f.decrypt(enc.encode("utf-8")).decode("utf-8").strip()
            except (InvalidToken, ValueError, TypeError):
                out[k] = ""

        return out

    def save(self, tokens: Dict[str, str]) -> None:
        path = self.path()
        f = self._fernet()

        encrypted: Dict[str, str] = {}
        for k in self.TOKEN_TYPES:
            raw = (tokens.get(k, "") or "").strip()
            if raw:
                encrypted[k] = f.encrypt(raw.encode("utf-8")).decode("utf-8")
            else:
                encrypted[k] = ""

        path.write_text(json.dumps(encrypted, indent=2) + "\n", encoding="utf-8")

    def get(self, token_type: str) -> str:
        return self.load().get(token_type, "").strip()

    def set(self, token_type: str, value: str) -> None:
        data = self.load()
        data[token_type] = (value or "").strip()
        self.save(data)
