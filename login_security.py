"""Helpers for storing and verifying the local login PIN."""

import base64
import hashlib
import hmac
import json
import secrets
from typing import Dict

import keyring
from keyring.errors import KeyringError, NoKeyringError, PasswordDeleteError


class LoginSecurityStore:
    """Stores a hashed local PIN in the system keyring."""

    KEYRING_SERVICE = "cf_iam_explorer_login"
    KEYRING_USERNAME = "local_pin_record"

    def _raise_keyring_unavailable(self, action: str, original_error: Exception | None = None) -> None:
        """Raise a consistent error when the system keyring is unavailable."""
        raise RuntimeError(
            f"Unable to {action} because no usable system keyring backend is available for the local PIN."
        ) from original_error

    def load(self) -> Dict[str, str]:
        """Load the saved PIN metadata from the system keyring."""
        try:
            raw = keyring.get_password(self.KEYRING_SERVICE, self.KEYRING_USERNAME)
        except (NoKeyringError, KeyringError) as err:
            self._raise_keyring_unavailable("access the local PIN", err)

        if not raw:
            return {}

        try:
            data = json.loads(raw)
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
        if len(cleaned) < 6 or len(cleaned) > 10:
            raise ValueError("PIN must be between 6 and 10 digits.")
        return cleaned

    @staticmethod
    def _derive_pin_hash(pin: str, salt: bytes) -> str:
        """Hash the PIN with PBKDF2 so the raw PIN is never stored."""
        derived = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, 300_000)
        return base64.b64encode(derived).decode("ascii")

    def set_pin(self, pin: str) -> None:
        """Save a newly configured PIN using a random salt and derived hash."""
        normalized_pin = self.validate_pin(pin)
        salt = secrets.token_bytes(16)
        payload = json.dumps({
            "pin_salt": base64.b64encode(salt).decode("ascii"),
            "pin_hash": self._derive_pin_hash(normalized_pin, salt),
        })

        try:
            keyring.set_password(self.KEYRING_SERVICE, self.KEYRING_USERNAME, payload)
        except (NoKeyringError, KeyringError) as err:
            self._raise_keyring_unavailable("save the local PIN", err)

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
        """Remove the configured PIN from the system keyring."""
        try:
            keyring.delete_password(self.KEYRING_SERVICE, self.KEYRING_USERNAME)
        except PasswordDeleteError:
            return
        except (NoKeyringError, KeyringError) as err:
            self._raise_keyring_unavailable("remove the local PIN", err)
