# Cloudflare IAM Explorer
# token store

import json
import os
from pathlib import Path
from typing import Dict, List, Optional

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

    def _raise_keyring_unavailable(self, action: str, original_error: Optional[Exception] = None) -> None:
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

        except (NoKeyringError, KeyringError) as err:
            self._raise_keyring_unavailable("access the encryption key", err)
        except Exception as err:
            raise RuntimeError(f"Unexpected error while accessing the system keyring: {err}") from err

    def _fernet(self) -> Fernet:
        return Fernet(self._get_or_create_master_key())

    @staticmethod
    def _best_effort_restrict_permissions(path: Path) -> None:
        """Tighten the token file permissions when the platform supports it."""
        try:
            os.chmod(path, 0o600)
        except OSError:
            return

    def load(self) -> Dict[str, str]:
        path = self.path()
        decrypted_tokens = {token_type: "" for token_type in self.TOKEN_TYPES}

        if not path.exists():
            return decrypted_tokens

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return decrypted_tokens

        if not isinstance(data, dict):
            return decrypted_tokens

        cipher = self._fernet()

        for token_type in self.TOKEN_TYPES:
            encrypted_value = data.get(token_type)
            if not isinstance(encrypted_value, str) or not encrypted_value.strip():
                continue

            try:
                decrypted_tokens[token_type] = cipher.decrypt(encrypted_value.encode("utf-8")).decode("utf-8").strip()
            except (InvalidToken, ValueError, TypeError):
                decrypted_tokens[token_type] = ""

        return decrypted_tokens

    def save(self, tokens: Dict[str, str]) -> None:
        path = self.path()
        cipher = self._fernet()

        encrypted: Dict[str, str] = {}
        for token_type in self.TOKEN_TYPES:
            raw_value = (tokens.get(token_type, "") or "").strip()
            if raw_value:
                encrypted[token_type] = cipher.encrypt(raw_value.encode("utf-8")).decode("utf-8")
            else:
                encrypted[token_type] = ""

        path.write_text(json.dumps(encrypted, indent=2) + "\n", encoding="utf-8")
        self._best_effort_restrict_permissions(path)

    def get(self, token_type: str) -> str:
        return self.load().get(token_type, "").strip()

    def set(self, token_type: str, value: str) -> None:
        data = self.load()
        data[token_type] = (value or "").strip()
        self.save(data)
