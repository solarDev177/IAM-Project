# Cloudflare IAM Explorer
# token store

import json
import os
from pathlib import Path
from typing import Dict, List


class TokenStore:
    TOKEN_TYPES: List[str] = ["Account Read", "Account Edit", "Group Read", "Group Edit"]

    def __init__(self, app_folder: str = "cf_iam_explorer", filename: str = "tokens.json"):
        self.app_folder = app_folder
        self.filename = filename

    def path(self) -> Path:
        base = Path(os.getenv("APPDATA") or (Path.home() / ".config"))
        folder = base / self.app_folder
        folder.mkdir(parents=True, exist_ok=True)
        return folder / self.filename

    def load(self) -> Dict[str, str]:
        path = self.path()
        if not path.exists():
            return {k: "" for k in self.TOKEN_TYPES}

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {k: "" for k in self.TOKEN_TYPES}

        out = {k: "" for k in self.TOKEN_TYPES}
        for k in self.TOKEN_TYPES:
            if isinstance(data.get(k), str):
                out[k] = data[k].strip()
        return out

    def save(self, tokens: Dict[str, str]) -> None:
        path = self.path()
        safe = {k: (tokens.get(k, "") or "").strip() for k in self.TOKEN_TYPES}

        print("TokenStore.save ->", path)  # DEBUG
        print("TokenStore.save data ->", {k: ("<set>" if v else "<empty>") for k, v in safe.items()})  # DEBUG

        path.write_text(json.dumps(safe, indent=2) + "\n", encoding="utf-8")

    def get(self, token_type: str) -> str:
        #  get token type
        return self.load().get(token_type, "").strip()

    def set(self, token_type: str, value: str) -> None:
        # Set token
        data = self.load()
        data[token_type] = (value or "").strip()
        self.save(data)
