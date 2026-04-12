"""Helpers for checking GitHub Releases and launching packaged app self-updates."""

import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from app_metadata import APP_NAME, APP_VERSION, GITHUB_REPOSITORY


class AppUpdateService:
    """Checks GitHub Releases and stages Windows self-updates for packaged builds."""

    GITHUB_API_TEMPLATE = "https://api.github.com/repos/{repo}/releases/latest"

    @staticmethod
    def _version_key(raw_version: str) -> Tuple[Tuple[int, object], ...]:
        """Convert a version string into a tuple for lightweight version comparisons."""
        tokens = re.findall(r"\d+|[a-zA-Z]+", (raw_version or "").lower())
        key: List[Tuple[int, object]] = []
        for token in tokens:
            if token.isdigit():
                key.append((0, int(token)))
            else:
                key.append((1, token))
        return tuple(key)

    # Check for any new versions. If yes, update:
    @classmethod
    def update_available(cls, current_version: str, latest_version: str) -> bool:
        """Return whether the GitHub release version is newer than the current app version."""
        if not latest_version:
            return False
        return cls._version_key(latest_version) > cls._version_key(current_version)

    @staticmethod
    def can_self_update() -> bool:
        """Return whether this runtime can perform a packaged self-update."""
        return bool(getattr(sys, "frozen", False)) and os.name == "nt"

    @staticmethod
    def current_executable() -> Path:
        """Return the current executable or interpreter path."""
        return Path(sys.executable).resolve()

    @classmethod
    def is_onedir_build(cls) -> bool:
        """Return whether the packaged app is running as a PyInstaller onedir build."""
        exe_path = cls.current_executable()
        return cls.can_self_update() and (exe_path.parent / "_internal").exists()

    @staticmethod
    def _github_latest_release() -> dict:
        """Fetch the latest GitHub release payload for the configured repository."""
        request = urllib.request.Request(
            AppUpdateService.GITHUB_API_TEMPLATE.format(repo=GITHUB_REPOSITORY),
            headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))

    @staticmethod
    def _normalize_tag(tag_name: str) -> str:
        """Normalize a GitHub release tag into a version-like string."""
        normalized = (tag_name or "").strip()
        return normalized[1:] if normalized.lower().startswith("v") else normalized

    @classmethod
    def _select_asset(cls, assets: List[dict]) -> Optional[dict]:
        """Choose the release asset that best matches the current packaged runtime."""
        if not assets:
            return None

        prefer_zip = cls.is_onedir_build()
        preferred_extensions = [".zip", ".exe"] if prefer_zip else [".exe", ".zip"]

        def score(asset: dict) -> Tuple[int, int]:
            name = str(asset.get("name") or "").lower()
            ext_score = 10
            for index, extension in enumerate(preferred_extensions):
                if name.endswith(extension):
                    ext_score = index
                    break

            name_score = 5
            if "cloudflareiamexplorer" in name.replace("-", "").replace("_", ""):
                name_score = 0
            elif "cloudflare" in name and "explorer" in name:
                name_score = 1
            return ext_score, name_score

        sorted_assets = sorted(
            (asset for asset in assets if asset.get("browser_download_url") and asset.get("name")),
            key=score,
        )

        for asset in sorted_assets:
            name = str(asset.get("name") or "").lower()
            if prefer_zip and name.endswith(".zip"):
                return asset
            if (not prefer_zip) and name.endswith(".exe"):
                return asset

        return sorted_assets[0] if sorted_assets else None

    @classmethod
    def inspect_update_state(cls) -> Dict[str, str]:
        """Check GitHub Releases and summarize whether an app update is available."""
        result: Dict[str, str] = {
            "current_version": APP_VERSION,
            "latest_version": APP_VERSION,
            "status": "unavailable",
            "message": "Packaged app updates are available only in Windows packaged builds.",
        }

        if not GITHUB_REPOSITORY:
            result["status"] = "unavailable"
            result["message"] = "No GitHub repository is configured for application updates."
            return result

        if not cls.can_self_update():
            return result

        release = cls._github_latest_release()
        latest_version = cls._normalize_tag(str(release.get("tag_name") or ""))
        asset = cls._select_asset(list(release.get("assets") or []))
        result.update({
            "latest_version": latest_version or APP_VERSION,
            "release_name": str(release.get("name") or latest_version or "Latest Release"),
        })

        if asset is None:
            result["status"] = "unavailable"
            result["message"] = "No compatible release asset was found on GitHub."
            return result

        result.update({
            "asset_name": str(asset.get("name") or ""),
            "asset_url": str(asset.get("browser_download_url") or ""),
        })

        if cls.update_available(APP_VERSION, latest_version):
            result["status"] = "update_available"
            result["message"] = f"Version {latest_version} is available on GitHub."
        else:
            result["status"] = "no_update"
            result["message"] = "Application is already on the latest GitHub release."

        return result

    @staticmethod
    def _download_asset(url: str, filename: str, target_dir: Path) -> Path:
        """Download a GitHub release asset into the provided staging directory."""
        target_dir.mkdir(parents=True, exist_ok=True)
        destination = target_dir / filename
        request = urllib.request.Request(url, headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}"})
        with urllib.request.urlopen(request, timeout=60) as response, open(destination, "wb") as output_file:
            output_file.write(response.read())
        return destination

    @staticmethod
    def _find_extracted_root(extract_dir: Path, executable_name: str) -> Path:
        """Locate the extracted directory that contains the replacement executable."""
        direct_match = extract_dir / executable_name
        if direct_match.exists():
            return extract_dir

        for candidate in extract_dir.rglob(executable_name):
            return candidate.parent

        return extract_dir

    @staticmethod
    def _write_updater_script(script_path: Path, contents: str) -> None:
        """Write the detached updater batch script to disk."""
        script_path.write_text(contents, encoding="utf-8")

    @classmethod
    def _launch_updater_script(cls, script_path: Path) -> None:
        """Launch the detached updater script without opening a console window."""
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        subprocess.Popen(
            ["cmd.exe", "/c", str(script_path)],
            creationflags=creationflags,
            cwd=str(script_path.parent),
        )

    @classmethod
    def _stage_onefile_update(cls, downloaded_asset: Path) -> Dict[str, str]:
        """Prepare a onefile executable replacement update."""
        current_exe = cls.current_executable()
        temp_dir = downloaded_asset.parent
        script_path = temp_dir / "apply_update.cmd"
        script = f"""@echo off
setlocal
set "TARGET_EXE={current_exe}"
set "NEW_EXE={downloaded_asset}"
set "WAIT_PID={os.getpid()}"

:waitloop
tasklist /FI "PID eq %WAIT_PID%" | find "%WAIT_PID%" >nul
if not errorlevel 1 (
    timeout /t 1 /nobreak >nul
    goto waitloop
)

copy /Y "%NEW_EXE%" "%TARGET_EXE%" >nul
start "" "%TARGET_EXE%"
del "%NEW_EXE%" >nul 2>nul
del "%~f0"
"""
        cls._write_updater_script(script_path, script)
        cls._launch_updater_script(script_path)
        return {
            "status": "update_started",
            "message": "Downloaded update and launched the onefile updater.",
        }

    @classmethod
    def _stage_onedir_update(cls, downloaded_asset: Path) -> Dict[str, str]:
        """Prepare an onedir folder replacement update from a zip asset."""
        current_exe = cls.current_executable()
        install_dir = current_exe.parent
        temp_dir = downloaded_asset.parent
        extract_dir = temp_dir / "extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(downloaded_asset, "r") as archive:
            archive.extractall(extract_dir)

        update_root = cls._find_extracted_root(extract_dir, current_exe.name)
        script_path = temp_dir / "apply_update.cmd"
        script = f"""@echo off
setlocal
set "TARGET_DIR={install_dir}"
set "UPDATE_DIR={update_root}"
set "TARGET_EXE={current_exe}"
set "WAIT_PID={os.getpid()}"

:waitloop
tasklist /FI "PID eq %WAIT_PID%" | find "%WAIT_PID%" >nul
if not errorlevel 1 (
    timeout /t 1 /nobreak >nul
    goto waitloop
)

robocopy "%UPDATE_DIR%" "%TARGET_DIR%" /E /R:2 /W:1 /NFL /NDL /NJH /NJS /NC /NS /NP >nul
start "" "%TARGET_EXE%"
rmdir /S /Q "{extract_dir}" >nul 2>nul
del "{downloaded_asset}" >nul 2>nul
del "%~f0"
"""
        cls._write_updater_script(script_path, script)
        cls._launch_updater_script(script_path)
        return {
            "status": "update_started",
            "message": "Downloaded update and launched the onedir updater.",
        }

    @classmethod
    def download_and_stage_update(cls, update_state: Dict[str, str]) -> Dict[str, str]:
        """Download the GitHub release asset and hand off installation to an external updater."""
        if update_state.get("status") != "update_available":
            return {
                "status": "skipped",
                "message": "No application update is currently available.",
            }

        asset_url = str(update_state.get("asset_url") or "").strip()
        asset_name = str(update_state.get("asset_name") or "").strip()
        if not asset_url or not asset_name:
            return {
                "status": "failed",
                "message": "Update metadata was missing a downloadable GitHub asset.",
            }

        temp_dir = Path(tempfile.mkdtemp(prefix="cf_iam_update_"))
        downloaded_asset = cls._download_asset(asset_url, asset_name, temp_dir)

        if cls.is_onedir_build():
            return cls._stage_onedir_update(downloaded_asset)
        return cls._stage_onefile_update(downloaded_asset)
