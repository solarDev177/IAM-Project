# Cloudflare IAM Explorer
# token store

import json
import os
from pathlib import Path
from typing import Dict

TOKEN_TYPES = ["Account Read", "Account Edit", "Group Read", "Group Edit"]

def token_file_path() -> Path:
    # Windows: C:\Users\<you>\AppData\Roaming\cf_iam_explorer\tokens.json
    # macOS/Linux: ~/.config/cf_iam_explorer/tokens.json
    base = Path(os.getenv("APPDATA") or Path.home() / ".config")
    folder = base / "cf_iam_explorer"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / "tokens.json"

def load_tokens() -> Dict[str, str]:
    path = token_file_path()
    if not path.exists():
        return {k: "" for k in TOKEN_TYPES}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {k: "" for k in TOKEN_TYPES}

    # Ensure all keys exist:
    out = {k: "" for k in TOKEN_TYPES}
    for k in TOKEN_TYPES:
        if isinstance(data.get(k), str):
            out[k] = data[k].strip()
    return out

def save_tokens(tokens: Dict[str, str]) -> None:
    path = token_file_path()
    safe = {k: (tokens.get(k, "") or "").strip() for k in TOKEN_TYPES}
    path.write_text(json.dumps(safe, indent=2), encoding="utf-8")