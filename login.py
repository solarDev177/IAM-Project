# Cloudflare IAM Explorer
# login page

import customtkinter as ctk
import threading
from tkinter import messagebox

from cloudflare_client import CloudflareClient
# from api_handler import CloudflareAPIError
from token_store import load_tokens
from token_manager import TokenManagerWindow
from main_app import App

class LoginWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Cloudflare IAM Login")
        self.geometry("520x320")
        self.resizable(False, False)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.configure(fg_color="#000000")

        self.account_id_var = ctk.StringVar()
        self.status_var = ctk.StringVar(value="")

        self._build_ui()

    def _build_ui(self):
        frame = ctk.CTkFrame(self, fg_color="#000000")
        frame.pack(fill="both", expand=True, padx=22, pady=22)

        ctk.CTkLabel(frame, text="Cloudflare IAM Explorer", text_color="#ffffff",
                     font=("Segoe UI", 20, "bold")).pack(anchor="w", pady=(0, 10))

        ctk.CTkLabel(frame, text="Account ID", text_color="#ffffff").pack(anchor="w")
        self.account_entry = ctk.CTkEntry(frame, textvariable=self.account_id_var, width=460,
                                          fg_color="#1a1a1a", border_color="#333333", text_color="#ffffff")
        self.account_entry.pack(anchor="w", pady=(6, 14))
        self.account_entry.bind("<Return>", lambda e: self.on_login())

        ctk.CTkLabel(frame, textvariable=self.status_var, text_color="#4ec9b0").pack(anchor="w", pady=(0, 10))

        btn_row = ctk.CTkFrame(frame, fg_color="#000000")
        btn_row.pack(anchor="w", pady=(8, 0))

        self.login_btn = ctk.CTkButton(btn_row, text="Continue", command=self.on_login,
                                       fg_color="#0078d4", hover_color="#106ebe", width=160)
        self.login_btn.pack(side="left", padx=(0, 10))

        ctk.CTkButton(btn_row, text="Manage Tokens", command=self.open_token_manager,
                      fg_color="#333333", hover_color="#444444", width=160).pack(side="left")

    def open_token_manager(self):
        TokenManagerWindow(self)

    def on_login(self):
        account_id = self.account_id_var.get().strip()
        if len(account_id) != 32:
            messagebox.showerror("Invalid Account ID", "Account ID must be 32 characters.")
            return

        tokens = load_tokens()
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
        self.withdraw()
        messagebox.showinfo("Connected", f"Connected to: {account_name}")

        # Pass account_id; main app can load tokens from file too (recommended)
        app = App(account_id=account_id)
        app.mainloop()
        self.destroy()

    def _fail(self, err: Exception):
        self.login_btn.configure(state="normal")
        self.status_var.set("")
        messagebox.showerror("Login Failed", str(err))

def main():
    LoginWindow().mainloop()

if __name__ == "__main__":
    main()
