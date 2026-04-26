"""Startup window that checks for g4f updates before showing the login screen."""

import threading
from tkinter import TclError, messagebox

import customtkinter as ctk

from app_metadata import APP_NAME
from app_update_service import AppUpdateService
from g4f_update_service import G4FUpdateService
from window_icon import WindowIconManager


class StartupWindow(ctk.CTkToplevel):
    """Shows a branded pre-launch window while checking for g4f updates."""

    def __init__(self, master=None, on_ready=None):
        super().__init__(master)
        self.title("Cloudflare IAM Explorer")
        self.geometry("560x320")
        self.resizable(False, False)
        self.should_launch_app = False
        self.on_ready = on_ready
        self._closed = False
        WindowIconManager.apply(self)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.configure(fg_color="#000000")

        self.status_var = ctk.StringVar(value="Checking for g4f updates...")
        self.detail_var = ctk.StringVar(value="Preparing startup checks...")

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        try:
            self.lift()
            self.focus_force()
            self.attributes("-topmost", True)
            self.after(180, lambda: self._window_alive() and self.attributes("-topmost", False))
        except Exception:
            pass
        self.after(120, self._start_update_check)

    def _build_ui(self) -> None:
        """Build the Cloudflare-styled startup window UI."""
        frame = ctk.CTkFrame(self, fg_color="#000000")
        frame.pack(fill="both", expand=True, padx=22, pady=22)

        ctk.CTkLabel(
            frame,
            text="Cloudflare IAM Explorer",
            text_color="#ffffff",
            font=("Segoe UI", 22, "bold"),
        ).pack(anchor="w", pady=(0, 8))

        ctk.CTkLabel(
            frame,
            text="Startup Check",
            text_color="#a0a0a0",
            font=("Segoe UI", 12),
        ).pack(anchor="w", pady=(0, 16))

        accent = ctk.CTkFrame(frame, fg_color="#ff8c1a", height=3, corner_radius=2)
        accent.pack(fill="x", pady=(0, 18))

        self.status_label = ctk.CTkLabel(
            frame,
            textvariable=self.status_var,
            text_color="#ff9f1c",
            font=("Segoe UI", 16, "bold"),
        )
        self.status_label.pack(anchor="w", pady=(0, 10))

        self.detail_label = ctk.CTkLabel(
            frame,
            textvariable=self.detail_var,
            text_color="#d0d0d0",
            font=("Segoe UI", 11),
            justify="left",
            wraplength=500,
        )
        self.detail_label.pack(anchor="w", pady=(0, 18))

        self.progress = ctk.CTkProgressBar(
            frame,
            mode="indeterminate",
            progress_color="#ff8c1a",
            fg_color="#333333",
            height=12,
        )
        self.progress.pack(fill="x")
        self.progress.start()

        button_row = ctk.CTkFrame(frame, fg_color="transparent")
        button_row.pack(fill="x", pady=(18, 0))

        self.continue_button = ctk.CTkButton(
            button_row,
            text="Continue",
            command=self._launch_app,
            fg_color="#ff8c1a",
            hover_color="#ff9f1c",
            text_color="#ffffff",
            width=140,
            state="disabled",
        )
        self.continue_button.pack(side="right")

    def _set_status(self, headline: str, detail: str = "", headline_color: str = "#ff9f1c") -> None:
        """Update the startup status labels."""
        self.status_var.set(headline)
        self.detail_var.set(detail)
        self.status_label.configure(text_color=headline_color)

    def _window_alive(self) -> bool:
        """Return whether the startup window still exists and is safe to target."""
        if self._closed:
            return False
        try:
            return bool(self.winfo_exists())
        except Exception:
            return False

    def focus_set(self):
        """Safely ignore delayed focus callbacks after the startup window has closed."""
        if not self._window_alive():
            return None
        try:
            return super().focus_set()
        except TclError:
            return None

    def focus_force(self):
        """Safely ignore delayed forced-focus callbacks after the startup window has closed."""
        if not self._window_alive():
            return None
        try:
            return super().focus_force()
        except TclError:
            return None

    def _queue_ui(self, callback) -> None:
        """Schedule a UI callback only if the startup window still exists."""
        try:
            if self._window_alive():
                self.after(0, lambda: self._window_alive() and callback())
        except Exception:
            pass

    def _hide_window(self) -> None:
        """Hide the startup window without relying on immediate destruction."""
        self._closed = True
        try:
            if self.winfo_exists():
                self.withdraw()
        except Exception:
            pass

    def _destroy_master(self) -> None:
        """Destroy the hidden root when the startup flow should exit completely."""
        try:
            if self.master is not None and self.master.winfo_exists():
                self.master.destroy()
        except Exception:
            pass

    def _start_update_check(self) -> None:
        """Launch the pre-login update checks in a background thread."""
        if not self._window_alive():
            return
        threading.Thread(target=self._run_app_update_check, daemon=True).start()

    def _run_app_update_check(self) -> None:
        """Check GitHub Releases for a packaged app update before the g4f check."""
        try:
            app_state = AppUpdateService.inspect_update_state()
            current_version = app_state.get("current_version", "Unknown")
            latest_version = app_state.get("latest_version", "Unknown")
            self._queue_ui(
                lambda: self._set_status(
                    "Checking App Updates",
                    f"Installed app: {current_version}\nLatest release: {latest_version}",
                )
            )
            self._queue_ui(lambda state=app_state: self._handle_app_update_state(state))
        except Exception as err:
            self._queue_ui(
                lambda error=err: self._continue_to_g4f_check(
                    f"Could not check app updates: {error}",
                )
            )

    def _handle_app_update_state(self, app_state: dict) -> None:
        """Prompt for packaged app updates when a newer GitHub release exists."""
        if not self._window_alive():
            return
        status = (app_state.get("status") or "").strip().lower()
        if status != "update_available":
            self._continue_to_g4f_check(app_state.get("message") or "")
            return

        self._set_status(
            "App Update Available",
            (
                f"Current version: {app_state.get('current_version', 'Unknown')}\n"
                f"Latest version: {app_state.get('latest_version', 'Unknown')}\n"
                f"Asset: {app_state.get('asset_name', '(unknown)')}"
            ),
        )
        try:
            approved = messagebox.askyesno(
                "Application Update Available",
                (
                    f"A newer release of {APP_NAME} is available on GitHub.\n\n"
                    f"Current version: {app_state.get('current_version', 'Unknown')}\n"
                    f"Latest version: {app_state.get('latest_version', 'Unknown')}\n\n"
                    "Download and install the update now?"
                ),
                parent=self,
            )
        except Exception:
            approved = False
        if not approved:
            self._continue_to_g4f_check("Skipped packaged app update.")
            return

        self._set_status("Installing App Update", "Downloading the new release and preparing installation...")
        threading.Thread(target=self._run_app_update_install, args=(app_state,), daemon=True).start()

    def _run_app_update_install(self, app_state: dict) -> None:
        """Download the GitHub release asset and stage the external updater."""
        try:
            result = AppUpdateService.download_and_stage_update(app_state)
            self._queue_ui(lambda payload=result: self._finish_app_update_install(payload))
        except Exception as err:
            self._queue_ui(
                lambda error=err: self._continue_to_g4f_check(
                    f"App update failed: {error}",
                )
            )

    def _finish_app_update_install(self, result: dict) -> None:
        """Finish the packaged update flow and close the app for replacement when needed."""
        if not self._window_alive():
            return
        if (result.get("status") or "").strip().lower() == "update_started":
            self.should_launch_app = False
            self.progress.stop()
            self._set_status("Installing Update", result.get("message") or "Closing so the updater can finish.")
            self.after(700, self._close_for_external_update)
            return

        self._continue_to_g4f_check(result.get("message") or "App update skipped.")

    def _close_for_external_update(self) -> None:
        """Close the startup flow entirely so the detached updater can replace the app."""
        self._hide_window()
        self._destroy_master()

    def _continue_to_g4f_check(self, prefix_message: str = "") -> None:
        """Resume the original g4f update check after the app-update branch completes."""
        if not self._window_alive():
            return
        if not G4FUpdateService.can_self_update():
            self._finish_update_check({
                "status": "no_update",
                "message": prefix_message or "App update status: no update available on GitHub.\nPackaged startup checks complete.",
            })
            return
        if prefix_message:
            self._set_status("Checking for g4f Updates", prefix_message)
            self.update_idletasks()
        threading.Thread(target=self._run_g4f_update_check, daemon=True).start()

    def _run_g4f_update_check(self) -> None:
        """Check for g4f updates and report the result back to the UI thread."""
        try:
            update_state = G4FUpdateService.inspect_update_state()
            installed = update_state.get("installed", "Not installed")
            latest = update_state.get("latest", "Unknown")
            self._queue_ui(
                lambda: self._set_status(
                    "Checking for Updates",
                    f"Installed g4f: {installed}\nLatest g4f: {latest}",
                )
            )

            result = G4FUpdateService.check_and_update(update_state)
            self._queue_ui(lambda: self._finish_update_check(result))
        except Exception as err:
            self._queue_ui(
                lambda error=err: self._finish_update_check({
                    "status": "failed",
                    "message": f"Could not check g4f updates: {error}",
                })
            )

    def _finish_update_check(self, result: dict) -> None:
        """Render the update result and continue into the login flow."""
        if not self._window_alive():
            return
        status = (result.get("status") or "").strip().lower()
        message = (result.get("message") or "").strip()

        if status == "updated":
            self._set_status("Launching App", f"{message}\nStartup checks complete.", "#ff9f1c")
        elif status == "failed":
            self._set_status("Launching App", message or "Update check failed. Launching app.", "#ff9f1c")
        elif status == "unavailable":
            self._set_status("Launching App", message or "Runtime updates are unavailable in this build.", "#ff9f1c")
        else:
            self._set_status("Launching App", message or "No g4f updates were found.", "#ff9f1c")

        self.progress.stop()
        self.should_launch_app = True
        self._set_status("Ready to Launch", message or "Startup checks complete. Press Continue to open the app.", "#ff9f1c")
        if hasattr(self, "continue_button") and self.continue_button.winfo_exists():
            self.continue_button.configure(state="normal")

    def _launch_app(self) -> None:
        """Close the startup window and allow the login app to launch."""
        if not self._window_alive():
            return
        if not self.should_launch_app:
            return
        self._hide_window()
        if self.on_ready is not None:
            try:
                self.on_ready()
            except Exception as err:
                self._closed = False
                try:
                    if self.winfo_exists():
                        self.deiconify()
                except Exception:
                    pass
                self._set_status(
                    "Startup Error",
                    f"Could not open the login window: {err}",
                    "#ff4d4f",
                )
                if hasattr(self, "continue_button") and self.continue_button.winfo_exists():
                    self.continue_button.configure(state="normal")

    def _on_close(self) -> None:
        """Close the startup window without launching the app."""
        self.should_launch_app = False
        self._hide_window()
        self._destroy_master()
