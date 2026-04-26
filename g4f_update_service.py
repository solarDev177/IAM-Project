"""Helpers for checking and installing g4f updates before app launch."""

import json
import re
import ssl
import subprocess
import sys
import urllib.request
from importlib.metadata import PackageNotFoundError, version
from typing import Dict, List, Tuple

try:
    import certifi
except ImportError:
    certifi = None


class G4FUpdateService:
    """Checks PyPI for g4f updates and installs them when the app is running from source."""

    PACKAGE_NAME = "g4f"
    PYPI_URL = "https://pypi.org/pypi/g4f/json"

    @staticmethod
    def installed_version() -> str:
        """Return the currently installed g4f version, or an empty string if it is missing."""
        try:
            return version(G4FUpdateService.PACKAGE_NAME)
        except PackageNotFoundError:
            return ""

    @staticmethod
    def _ssl_context() -> ssl.SSLContext:
        """Build a verified SSL context with a certifi fallback for packaged or isolated runtimes."""
        if certifi is not None:
            return ssl.create_default_context(cafile=certifi.where())
        return ssl.create_default_context()

    @staticmethod
    def latest_version() -> str:
        """Fetch the latest published g4f version from PyPI."""
        request = urllib.request.Request(
            G4FUpdateService.PYPI_URL,
            headers={"User-Agent": "Cloudflare-IAM-Explorer/1.0"},
        )
        with urllib.request.urlopen(request, timeout=8, context=G4FUpdateService._ssl_context()) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return str((payload.get("info") or {}).get("version") or "").strip()

    @staticmethod
    def _version_key(raw_version: str) -> Tuple[Tuple[int, object], ...]:
        """Convert a version string into a tuple that is stable enough for upgrade checks."""
        tokens = re.findall(r"\d+|[a-zA-Z]+", (raw_version or "").lower())
        key: List[Tuple[int, object]] = []
        for token in tokens:
            if token.isdigit():
                key.append((0, int(token)))
            else:
                key.append((1, token))
        return tuple(key)

    @classmethod
    def update_available(cls, installed: str, latest: str) -> bool:
        """Return whether the latest published version is newer than the installed version."""
        if not latest:
            return False
        if not installed:
            return True
        return cls._version_key(latest) > cls._version_key(installed)

    @staticmethod
    def can_self_update() -> bool:
        """Return whether this runtime can safely update g4f in-place."""
        return not bool(getattr(sys, "frozen", False))

    @staticmethod
    def install_update() -> Tuple[bool, str]:
        """Run pip to install or upgrade g4f for the current Python environment."""
        command = [sys.executable, "-m", "pip", "install", "--upgrade", G4FUpdateService.PACKAGE_NAME]
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        output = (completed.stdout or "").strip() or (completed.stderr or "").strip()
        return completed.returncode == 0, output

    @classmethod
    def inspect_update_state(cls) -> Dict[str, str]:
        """Fetch the current and latest g4f versions and summarize the update state."""
        installed = cls.installed_version()
        latest = cls.latest_version()

        result: Dict[str, str] = {
            "installed": installed or "Not installed",
            "latest": latest or "Unknown",
            "status": "no_update",
            "message": "g4f is already up to date.",
        }

        if cls.update_available(installed, latest):
            result["status"] = "update_available"
            result["message"] = f"g4f {latest} is available."

        return result

    @classmethod
    def check_and_update(cls, update_state: Dict[str, str] = None) -> Dict[str, str]:
        """Check for a newer g4f release and install it when possible."""
        result = dict(update_state or cls.inspect_update_state())
        installed = result.get("installed", "Not installed")
        latest = result.get("latest", "Unknown")

        if result.get("status") != "update_available":
            return result

        if not cls.can_self_update():
            result["status"] = "unavailable"
            result["message"] = "Packaged build detected. g4f updates are available only when running from source."
            return result

        success, output = cls.install_update()
        if success:
            result["status"] = "updated"
            result["message"] = f"Updated g4f from {installed or 'missing'} to {latest}."
            result["output"] = output
            return result

        result["status"] = "failed"
        result["message"] = f"g4f update failed. Launching with {installed or 'the current'} version."
        result["output"] = output
        return result
