"""Helpers for storing and verifying the local login PIN."""

import base64
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Dict


class LoginSecurityStore:
    """Stores a hashed local PIN used to gate access to the desktop app."""

    def __init__(self, app_folder: str = "cf_iam_explorer", filename: str = "login_security.json"):
        """Initialize the storage location for the local login PIN metadata."""
        self.app_folder = app_folder
        self.filename = filename

    def path(self) -> Path:
        """Return the settings path used for login PIN metadata."""
        base = Path(os.getenv("APPDATA") or (Path.home() / ".config"))
        folder = base / self.app_folder
        folder.mkdir(parents=True, exist_ok=True)
        return folder / self.filename

    def load(self) -> Dict[str, str]:
        """Load the saved PIN metadata from disk."""
        path = self.path()
        if not path.exists():
            return {}

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

        return data if isinstance(data, dict) else {}

    def is_pin_enabled(self) -> bool:
        """Return whether a local PIN has been configured."""
        data = self.load()
        return bool(data.get("pin_hash") and data.get("pin_salt"))

    @staticmethod
    def validate_pin(pin: str) -> str:
        """Validate the user-provided PIN before it is saved or checked."""
        cleaned = (pin or "").strip()
        if not cleaned.isdigit():
            raise ValueError("PIN must contain only numbers.")
        if len(cleaned) < 4 or len(cleaned) > 10:
            raise ValueError("PIN must be between 4 and 10 digits.")
        return cleaned

    @staticmethod
    def _derive_pin_hash(pin: str, salt: bytes) -> str:
        """Hash the PIN with PBKDF2 so the raw PIN is never stored."""
        derived = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, 200_000)
        return base64.b64encode(derived).decode("ascii")

    def set_pin(self, pin: str) -> None:
        """Save a newly configured PIN using a random salt and derived hash."""
        normalized_pin = self.validate_pin(pin)
        salt = secrets.token_bytes(16)
        payload = {
            "pin_salt": base64.b64encode(salt).decode("ascii"),
            "pin_hash": self._derive_pin_hash(normalized_pin, salt),
        }
        self.path().write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def verify_pin(self, pin: str) -> bool:
        """Check whether the provided PIN matches the stored login PIN."""
        data = self.load()
        pin_hash = data.get("pin_hash") or ""
        pin_salt = data.get("pin_salt") or ""
        if not pin_hash or not pin_salt:
            return False

        try:
            normalized_pin = self.validate_pin(pin)
            salt = base64.b64decode(pin_salt.encode("ascii"))
        except Exception:
            return False

        candidate_hash = self._derive_pin_hash(normalized_pin, salt)
        return hmac.compare_digest(pin_hash, candidate_hash)

    def clear_pin(self) -> None:
        """Remove the configured PIN from local storage."""
        self.path().write_text("{}\n", encoding="utf-8")
