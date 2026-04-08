# Cloudflare IAM Explorer
# login page

import customtkinter as ctk
import threading
from tkinter import messagebox, simpledialog

from cloudflare_client import CloudflareClient
# from api_handler import CloudflareAPIError
from login_security import LoginSecurityStore
from token_store import TokenStore
from token_manager import TokenManagerWindow
from main_app import App

class LoginWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Cloudflare IAM Login")
        self.geometry("560x430")
        self.resizable(False, False)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.configure(fg_color="#000000")

        self.account_id_var = ctk.StringVar()
        self.pin_var = ctk.StringVar()
        self.status_var = ctk.StringVar(value="")
        self.pin_status_var = ctk.StringVar(value="")
        self.security_store = LoginSecurityStore()

        self._build_ui()
        self._refresh_pin_status()

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
            text_color="#4ec9b0",
            font=("Segoe UI", 11),
            wraplength=480,
            justify="left",
        ).pack(anchor="w", pady=(0, 8))

        ctk.CTkLabel(frame, textvariable=self.status_var, text_color="#4ec9b0").pack(anchor="w", pady=(0, 10))

        btn_row = ctk.CTkFrame(frame, fg_color="#000000")
        btn_row.pack(anchor="w", pady=(8, 0))

        self.login_btn = ctk.CTkButton(btn_row, text="Continue", command=self.on_login,
                                       fg_color="#0078d4", hover_color="#106ebe", width=160)
        self.login_btn.pack(side="left", padx=(0, 10))

        ctk.CTkButton(btn_row, text="Manage Tokens", command=self.open_token_manager,
                      fg_color="#333333", hover_color="#444444", width=160).pack(side="left")

        ctk.CTkButton(btn_row, text="Set / Change PIN", command=self.set_or_change_pin,
                      fg_color="#333333", hover_color="#444444", width=160).pack(side="left", padx=(10, 0))

        ctk.CTkButton(frame, text="Remove PIN", command=self.remove_pin,
                      fg_color="#333333", hover_color="#444444", width=160).pack(anchor="w", pady=(12, 0))

    def open_token_manager(self):
        TokenManagerWindow(self)

    def _refresh_pin_status(self):
        """Update the login screen with the current local PIN status."""
        if self.security_store.is_pin_enabled():
            self.pin_status_var.set("Local PIN protection is enabled for this workstation login.")
        else:
            self.pin_status_var.set("No local PIN is set. You can add one for an extra login check on this device.")

    def _prompt_pin_value(self, title: str, prompt: str):
        """Prompt the user for a numeric PIN value."""
        return simpledialog.askstring(title, prompt, parent=self, show="•")

    def set_or_change_pin(self):
        """Create a new local PIN or replace the current one after verification."""
        if self.security_store.is_pin_enabled():
            current_pin = self._prompt_pin_value("Current PIN", "Enter the current PIN:")
            if current_pin is None:
                return
            if not self.security_store.verify_pin(current_pin):
                messagebox.showerror("Invalid PIN", "The current PIN was incorrect.", parent=self)
                return

        new_pin = self._prompt_pin_value("Set PIN", "Enter a new numeric PIN (4-10 digits):")
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
        if not self.security_store.verify_pin(current_pin):
            messagebox.showerror("Invalid PIN", "The current PIN was incorrect.", parent=self)
            return
        if not messagebox.askyesno("Remove PIN", "Remove the local login PIN from this device?", parent=self):
            return

        self.security_store.clear_pin()
        self.pin_var.set("")
        self._refresh_pin_status()
        messagebox.showinfo("PIN Removed", "The local login PIN has been removed.", parent=self)

    def on_login(self):
        """Validate the local PIN, then verify account access with Cloudflare."""
        account_id = self.account_id_var.get().strip()
        if len(account_id) != 32:
            messagebox.showerror("Invalid Account ID", "Account ID must be 32 characters.")
            return

        if self.security_store.is_pin_enabled():
            entered_pin = self.pin_var.get().strip()
            if not entered_pin:
                messagebox.showerror("Missing PIN", "Enter the local PIN to continue.", parent=self)
                return
            if not self.security_store.verify_pin(entered_pin):
                messagebox.showerror("Invalid PIN", "The local PIN was incorrect.", parent=self)
                return

        store = TokenStore()
        tokens = store.load()
        account_read = tokens.get("Account Read", "").strip()

        if not account_read:
            messagebox.showerror("Missing Token", "Please save an Account Read token first (Manage Tokens).")
            return

        self.login_btn.configure(state="disabled")
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
        self.status_var.set("")
        self.pin_var.set("")
        messagebox.showinfo("Connected", f"Connected to: {account_name}")

        self.withdraw()  # hide login root

        app = App(master=self, account_id=account_id)

        def on_close():
            app.destroy()
            self.destroy()  # exit the program

        app.protocol("WM_DELETE_WINDOW", on_close)

    def _fail(self, err: Exception):
        self.login_btn.configure(state="normal")
        self.status_var.set("")
        messagebox.showerror("Login Failed", str(err))
