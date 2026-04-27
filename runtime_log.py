"""Small helper for writing user-accessible runtime breadcrumbs in packaged builds."""

import re
import time
from pathlib import Path


RUNTIME_ERROR_LOG = Path.home() / "CloudflareIAMExplorer-runtime.log"


def runtime_log_path() -> Path:
    """Return the shared runtime log path used across packaged runs."""
    return RUNTIME_ERROR_LOG


def clear_runtime_log() -> None:
    """Delete the shared runtime log when the user requests local-data cleanup."""
    if RUNTIME_ERROR_LOG.exists():
        RUNTIME_ERROR_LOG.unlink()


def _mask_email(match: re.Match[str]) -> str:
    """Mask an email address while keeping enough context to troubleshoot safely."""
    local_part = match.group(1)
    domain = match.group(2)
    if len(local_part) <= 2:
        local_mask = "*" * len(local_part)
    else:
        local_mask = f"{local_part[:2]}***"
    return f"{local_mask}@{domain}"


def sanitize_runtime_text(text: str) -> str:
    """Best-effort scrub common identifiers before they are written to disk."""
    sanitized = str(text or "")
    sanitized = re.sub(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", _mask_email, sanitized)
    sanitized = re.sub(r"\b([a-fA-F0-9]{4})[a-fA-F0-9]{20,}([a-fA-F0-9]{4})\b", r"\1***\2", sanitized)
    sanitized = re.sub(r"\b([A-Za-z0-9_-]{4})[A-Za-z0-9_-]{28,}([A-Za-z0-9_-]{4})\b", r"\1***\2", sanitized)
    return sanitized


def append_runtime_log(header: str, details: str = "") -> None:
    """Append one timestamped runtime entry to the shared log file."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with RUNTIME_ERROR_LOG.open("a", encoding="utf-8") as log_file:
            log_file.write(f"[{timestamp}] {sanitize_runtime_text(header)}\n")
            if details:
                log_file.write(f"{sanitize_runtime_text(details)}\n")
            log_file.write("\n")
    except Exception:
        pass
