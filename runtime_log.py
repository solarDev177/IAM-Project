"""Small helper for writing user-accessible runtime breadcrumbs in packaged builds."""

import time
from pathlib import Path


RUNTIME_ERROR_LOG = Path.home() / "CloudflareIAMExplorer-runtime.log"


def append_runtime_log(header: str, details: str = "") -> None:
    """Append one timestamped runtime entry to the shared log file."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with RUNTIME_ERROR_LOG.open("a", encoding="utf-8") as log_file:
            log_file.write(f"[{timestamp}] {header}\n")
            if details:
                log_file.write(f"{details}\n")
            log_file.write("\n")
    except Exception:
        pass
