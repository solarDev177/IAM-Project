# Cloudflare IAM Explorer
# login page

import customtkinter as ctk
import re
import threading
import time
from tkinter import messagebox, simpledialog

from cloudflare_client import CloudflareClient
# from api_handler import CloudflareAPIError
from login_security import LoginSecurityStore
from token_store import TokenStore
from token_manager import TokenManagerWindow
from main_app import App
from window_icon import WindowIconManager

class LoginWindow(ctk.CTkToplevel):
    def __init__(self, master=None):
        super().__init__(master)
        self.title("Cloudflare IAM Login")
        self.geometry("560x430")
        self.resizable(False, False)
        WindowIconManager.apply(self)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.configure(fg_color="#000000")

        self.account_id_var = ctk.StringVar()
        self.pin_var = ctk.StringVar()
        self.status_var = ctk.StringVar(value="")
        self.pin_status_var = ctk.StringVar(value="")
        self.security_store = LoginSecurityStore()
        self._pin_failures = 0
        self._pin_lock_until = 0.0
        self._login_in_progress = False
        self._app_launched = False

        self._build_ui()
        self._refresh_pin_status()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        try:
            self.lift()
            self.focus_force()
            self.attributes("-topmost", True)
            self.after(180, lambda: self.winfo_exists() and self.attributes("-topmost", False))
        except Exception:
            pass

    def _build_ui(self):
        frame = ctk.CTkFrame(self, fg_color="#000000")
        frame.pack(fill="both", expand=True, padx=22, pady=22)

        ctk.CTkLabel(frame, text="Cloudflare IAM Explorer", text_color="#ffffff",
                     font=("Segoe UI", 20, "bold")).pack(anchor="w", pady=(0, 10))

        ctk.CTkLabel(frame, text="Account ID", text_color="#ffffff").pack(anchor="w")
        self.account_entry = ctk.CTkEntry(frame, textvariable=self.account_id_var, width=460,
                                          fg_color="#1a1a1a", border_color="#333333", text_color="#ffffff")
        self.account_entry.pack(anchor="w", pady=(6, 6))
        self.account_entry.bind("<Return>", lambda e: self.on_login())

        ctk.CTkLabel(
            frame,
            text="Enter the Cloudflare Account ID for the tenant you want to manage, not a member ID.",
            text_color="#a0a0a0",
            font=("Segoe UI", 11),
            wraplength=480,
            justify="left",
        ).pack(anchor="w", pady=(0, 14))

        ctk.CTkLabel(frame, text="Local PIN (optional)", text_color="#ffffff").pack(anchor="w")
        self.pin_entry = ctk.CTkEntry(
            frame,
            textvariable=self.pin_var,
            width=220,
            show="•",
            fg_color="#1a1a1a",
            border_color="#333333",
            text_color="#ffffff",
        )
        self.pin_entry.pack(anchor="w", pady=(6, 6))
        self.pin_entry.bind("<Return>", lambda e: self.on_login())

        ctk.CTkLabel(
            frame,
            textvariable=self.pin_status_var,
            text_color="#ff9f1c",
            font=("Segoe UI", 11),
            wraplength=480,
            justify="left",
        ).pack(anchor="w", pady=(0, 8))

        ctk.CTkLabel(frame, textvariable=self.status_var, text_color="#ff9f1c").pack(anchor="w", pady=(0, 10))

        btn_row = ctk.CTkFrame(frame, fg_color="#000000")
        btn_row.pack(anchor="w", pady=(8, 0))

        self.login_btn = ctk.CTkButton(btn_row, text="Continue", command=self.on_login,
                                       fg_color="#ff8c1a", hover_color="#ff9f1c", width=160)
        self.login_btn.pack(side="left", padx=(0, 10))

        ctk.CTkButton(btn_row, text="Manage Tokens", command=self.open_token_manager,
                      fg_color="#333333", hover_color="#444444", width=160).pack(side="left")

        ctk.CTkButton(btn_row, text="Set / Change PIN", command=self.set_or_change_pin,
                      fg_color="#333333", hover_color="#444444", width=160).pack(side="left", padx=(10, 0))

        ctk.CTkButton(frame, text="Remove PIN", command=self.remove_pin,
                      fg_color="#333333", hover_color="#444444", width=160).pack(anchor="w", pady=(12, 0))

    def open_token_manager(self):
        TokenManagerWindow(self)

    def _set_login_controls_enabled(self, enabled: bool) -> None:
        """Enable or disable the login controls during account verification."""
        state = "normal" if enabled else "disabled"
        self.login_btn.configure(state=state)
        self.account_entry.configure(state=state)
        self.pin_entry.configure(state=state)

    def _refresh_pin_status(self):
        """Update the login screen with the current local PIN status."""
        if self.security_store.is_pin_enabled():
            self.pin_status_var.set("Local PIN protection is enabled for this workstation login.")
        else:
            self.pin_status_var.set("No local PIN is set. You can add one for an extra login check on this device.")

    def _prompt_pin_value(self, title: str, prompt: str):
        """Prompt the user for a numeric PIN value."""
        return simpledialog.askstring(title, prompt, parent=self, show="•")

    def _pin_lock_remaining_seconds(self) -> int:
        """Return the remaining lockout time after repeated PIN failures."""
        remaining = self._pin_lock_until - time.time()
        return max(0, int(remaining + 0.999))

    def _record_pin_failure(self) -> None:
        """Increase the PIN failure counter and apply a short lockout when needed."""
        self._pin_failures += 1
        if self._pin_failures < 3:
            return

        lock_seconds = min(60, 5 * (2 ** (self._pin_failures - 3)))
        self._pin_lock_until = time.time() + lock_seconds

    def _reset_pin_failures(self) -> None:
        """Clear the PIN failure counter after a successful verification."""
        self._pin_failures = 0
        self._pin_lock_until = 0.0

    def _verify_pin_or_warn(self, pin_value: str, missing_message: str) -> bool:
        """Verify the PIN with lockout protection and user-facing error messages."""
        remaining = self._pin_lock_remaining_seconds()
        if remaining:
            messagebox.showerror(
                "PIN Locked",
                f"Too many incorrect PIN attempts. Try again in {remaining} seconds.",
                parent=self,
            )
            return False

        if not pin_value:
            messagebox.showerror("Missing PIN", missing_message, parent=self)
            return False

        if self.security_store.verify_pin(pin_value):
            self._reset_pin_failures()
            return True

        self._record_pin_failure()
        remaining = self._pin_lock_remaining_seconds()
        if remaining:
            messagebox.showerror(
                "PIN Locked",
                f"The PIN was incorrect. Try again in {remaining} seconds.",
                parent=self,
            )
        else:
            messagebox.showerror("Invalid PIN", "The PIN was incorrect.", parent=self)
        return False

    def set_or_change_pin(self):
        """Create a new local PIN or replace the current one after verification."""
        if self.security_store.is_pin_enabled():
            current_pin = self._prompt_pin_value("Current PIN", "Enter the current PIN:")
            if current_pin is None:
                return
            if not self._verify_pin_or_warn(current_pin, "Enter the current PIN to continue."):
                return

        new_pin = self._prompt_pin_value("Set PIN", "Enter a new numeric PIN (6-10 digits):")
        if new_pin is None:
            return

        confirm_pin = self._prompt_pin_value("Confirm PIN", "Re-enter the new PIN:")
        if confirm_pin is None:
            return

        if new_pin != confirm_pin:
            messagebox.showerror("PIN Mismatch", "The PIN values did not match.", parent=self)
            return

        try:
            self.security_store.set_pin(new_pin)
        except Exception as e:
            messagebox.showerror("PIN Error", str(e), parent=self)
            return

        self.pin_var.set("")
        self._refresh_pin_status()
        messagebox.showinfo("PIN Saved", "The local login PIN has been updated.", parent=self)

    def remove_pin(self):
        """Remove the configured local PIN after confirming the current PIN."""
        if not self.security_store.is_pin_enabled():
            messagebox.showinfo("No PIN", "No local PIN is currently set.", parent=self)
            return

        current_pin = self._prompt_pin_value("Remove PIN", "Enter the current PIN to remove it:")
        if current_pin is None:
            return
        if not self._verify_pin_or_warn(current_pin, "Enter the current PIN to remove it."):
            return
        if not messagebox.askyesno("Remove PIN", "Remove the local login PIN from this device?", parent=self):
            return

        self.security_store.clear_pin()
        self.pin_var.set("")
        self._refresh_pin_status()
        messagebox.showinfo("PIN Removed", "The local login PIN has been removed.", parent=self)

    def on_login(self):
        """Validate the local PIN, then verify account access with Cloudflare."""
        if self._login_in_progress or self._app_launched:
            return

        account_id = self.account_id_var.get().strip()
        if not re.fullmatch(r"[0-9a-fA-F]{32}", account_id):
            messagebox.showerror("Invalid Account ID", "Account ID must be a 32-character hexadecimal value.")
            return

        if self.security_store.is_pin_enabled():
            entered_pin = self.pin_var.get().strip()
            if not self._verify_pin_or_warn(entered_pin, "Enter the local PIN to continue."):
                return

        store = TokenStore()
        tokens = store.load()
        account_read = tokens.get("Account Read", "").strip()

        if not account_read:
            messagebox.showerror("Missing Token", "Please save an Account Read token first (Manage Tokens).")
            return

        self._login_in_progress = True
        self._set_login_controls_enabled(False)
        self.status_var.set("Verifying account…")
        self.update_idletasks()

        def worker():
            try:
                cf = CloudflareClient(account_read)

                # Verify token is valid for this account
                cf.verify_token_for_account(account_id)

                # Confirm the account exists & is accessible
                acct = cf.get_account(account_id)["result"]
                name = acct.get("name", "(unknown)")

                self.after(0, lambda: self._launch(account_id, name))
            except Exception as e:
                self.after(0, lambda err=e: self._fail(err))

        threading.Thread(target=worker, daemon=True).start()

    def _launch(self, account_id: str, account_name: str):
        if self._app_launched:
            return

        self._login_in_progress = False
        self.status_var.set("")
        self.pin_var.set("")
        messagebox.showinfo("Connected", f"Connected to: {account_name}")

        app_master = self.master if self.master is not None and self.master.winfo_exists() else self
        try:
            app = App(master=app_master, account_id=account_id)
        except Exception as err:
            self._app_launched = False
            self._set_login_controls_enabled(True)
            self.deiconify()
            try:
                self.lift()
                self.focus_force()
            except Exception:
                pass
            messagebox.showerror("Application Launch Failed", str(err), parent=self)
            return

        self._app_launched = True
        self._app_window = app
        if app_master is not None:
            try:
                app_master._main_app = app
            except Exception:
                pass

        def on_close():
            app.destroy()
            if app_master is not None and app_master.winfo_exists():
                app_master.destroy()

        app.protocol("WM_DELETE_WINDOW", on_close)

        self.withdraw()

        try:
            app.deiconify()
            app.update_idletasks()
            app.state("normal")
            app.lift()
            app.focus_force()
            app.attributes("-topmost", True)
            app.after(180, lambda: app.winfo_exists() and app.attributes("-topmost", False))
            app.after(320, lambda: self._finalize_app_launch(app))
        except Exception as err:
            self._app_launched = False
            self._set_login_controls_enabled(True)
            try:
                if app.winfo_exists():
                    app.destroy()
            except Exception:
                pass
            self.deiconify()
            try:
                self.lift()
                self.focus_force()
            except Exception:
                pass
            messagebox.showerror("Application Launch Failed", str(err), parent=self)

    def _finalize_app_launch(self, app: App) -> None:
        """Destroy the login window only after the main app survives its first presentation cycle."""
        try:
            if app is None or not app.winfo_exists():
                self._app_launched = False
                self._set_login_controls_enabled(True)
                self.deiconify()
                self.lift()
                self.focus_force()
                messagebox.showerror(
                    "Application Launch Failed",
                    "The main window did not stay open. Please try again.",
                    parent=self,
                )
                return
        except Exception:
            self._app_launched = False
            self._set_login_controls_enabled(True)
            self.deiconify()
            try:
                self.lift()
                self.focus_force()
            except Exception:
                pass
            messagebox.showerror(
                "Application Launch Failed",
                "The main window could not be verified after launch.",
                parent=self,
            )
            return

        self.destroy()

    def _fail(self, err: Exception):
        self._login_in_progress = False
        self._set_login_controls_enabled(True)
        self.status_var.set("")
        messagebox.showerror("Login Failed", str(err))

    def _on_close(self) -> None:
        """Close the login window and shut down the hidden root if present."""
        self.destroy()
        if self.master is not None and self.master.winfo_exists():
            self.master.destroy()
