# Cloudflare IAM Explorer
# main app

import customtkinter as ctk
import threading
import tkinter as tk
from tkinter import messagebox
from cloudflare_client import CloudflareClient


class App(ctk.CTk):
    # ---------- Initialization ----------
    # Change: have the class taken in an account ID: account_id: str
    def __init__(self, account_id: str, token: str):
        super().__init__()
        self.title("Cloudflare IAM Explorer (Tkinter)")
        self.geometry("980x620")

        self.initial_account_id = account_id

        self.tokens = {
            "Account Read": tk.StringVar(value=token), # pre-fill token
            "Account Edit": tk.StringVar(),
            "Group Read": tk.StringVar(),
            "Group Edit": tk.StringVar(),
        }
        self.selected_token_name = tk.StringVar(value="Account Read")

        self.accounts = []   # list of dicts from API
        self.selected_account_id = tk.StringVar(value=account_id)

        self._build_ui()

    # ---------- UI ----------
    def _build_ui(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.configure(fg_color="#000000")

        top = ctk.CTkFrame(self, fg_color="#000000")
        top.pack(fill="x", padx=12, pady=12)

        # Token selector
        ctk.CTkLabel(top, text="Token type:", text_color="#ffffff").grid(row=0, column=0, sticky="w", padx=(0, 6))
        token_combo = ctk.CTkComboBox(
            top,
            variable=self.selected_token_name,
            values=list(self.tokens.keys()),
            state="readonly",
            width=140,
            fg_color="#1a1a1a",
            button_color="#0078d4",
            button_hover_color="#106ebe",
            border_color="#333333"
        )
        token_combo.grid(row=0, column=1, padx=(0, 12), sticky="w")
        token_combo.configure(command=lambda e: self._refresh_token_entry())

        # Token entry
        ctk.CTkLabel(top, text="Token value:", text_color="#ffffff").grid(row=0, column=2, sticky="w", padx=(0, 6))
        self.token_entry = ctk.CTkEntry(top, width=500, show="•", fg_color="#1a1a1a", border_color="#333333",
                                        text_color="#ffffff")
        self.token_entry.grid(row=0, column=3, sticky="we", padx=(0, 6))

        self.show_token = tk.BooleanVar(value=False)
        show_cb = ctk.CTkCheckBox(top, text="Show", variable=self.show_token, command=self._toggle_show, width=80,
                                  fg_color="#0078d4", hover_color="#106ebe", text_color="#ffffff")
        show_cb.grid(row=0, column=4, padx=(8, 0))

        # Buttons row
        btns = ctk.CTkFrame(top, fg_color="#000000")
        btns.grid(row=1, column=0, columnspan=5, sticky="w", pady=(10, 0))

        ctk.CTkButton(btns, text="Verify Token", command=self.on_verify, fg_color="#0078d4",hover_color="#106ebe").pack(side="left", padx=(0, 8))
        ctk.CTkButton(btns, text="List Accounts", command=self.on_list_accounts, fg_color="#0078d4",hover_color="#106ebe").pack(side="left", padx=(0, 8))
        ctk.CTkButton(btns, text="List Members", command=self.on_list_members, fg_color="#0078d4",hover_color="#106ebe").pack(side="left", padx=(0, 8))
        ctk.CTkButton(btns, text="List IAM User Groups", command=self.on_list_groups, fg_color="#0078d4",hover_color="#106ebe").pack(side="left")

        top.columnconfigure(3, weight=1)

        # Account picker
        mid = ctk.CTkFrame(self, fg_color="#000000")
        mid.pack(fill="x", padx=12, pady=(0, 12))

        ctk.CTkLabel(mid, text="Selected account:", text_color="#ffffff").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.account_combo = ctk.CTkComboBox(mid, values=[], state="readonly", width=400, fg_color="#1a1a1a",button_color="#0078d4", button_hover_color="#106ebe",border_color="#333333")
        self.account_combo.grid(row=0, column=1, padx=(0, 12), sticky="w")
        # Change: set _build_ui to show the chosen account ID:
        self.account_combo.configure(values=[f"Selected ({self.initial_account_id})"])
        self.account_combo.set(f"Selected ({self.initial_account_id})")

        self.status_var = tk.StringVar(value="Ready.")
        ctk.CTkLabel(mid, textvariable=self.status_var, text_color="#4ec9b0").grid(row=0, column=2, sticky="w")

        # Output area
        body = ctk.CTkFrame(self, fg_color="#000000")
        body.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        ctk.CTkLabel(body, text="Output:", text_color="#ffffff").pack(anchor="w")
        self.output = ctk.CTkTextbox(body, wrap="none", fg_color="#1a1a1a", border_color="#333333",text_color="#ffffff")
        self.output.pack(fill="both", expand=True, pady=(6, 0))

        # Initialize entry with selected token var
        self._refresh_token_entry()

    def _toggle_show(self):
        self.token_entry.configure(show="" if self.show_token.get() else "•")

    def _refresh_token_entry(self):
        # Save current entry into its token var before switching
        current_name = self.selected_token_name.get()
        for name, var in self.tokens.items():
            if name == current_name:
                var.set(self.token_entry.get().strip())

        # Load selected token into entry
        token = self.tokens[self.selected_token_name.get()].get()
        self.token_entry.delete(0, "end")
        self.token_entry.insert(0, token)

    def _set_status(self, text: str):
        self.status_var.set(text)

    def _append(self, text: str):
        self.output.insert("end", text + "\n")
        self.output.see("end")

    # ---------- Helpers ----------
    def _get_client(self) -> CloudflareClient:
        self._refresh_token_entry()
        token = self.tokens[self.selected_token_name.get()].get().strip()
        if not token:
            raise ValueError("Please paste a token first.")
        return CloudflareClient(token)

    def _run_bg(self, label: str, func):
        """Run a function in background, safely updating UI."""
        self._set_status(label + "...")
        self._append(f"\n== {label} ==")

        def worker():
            try:
                result = func()
                self.after(0, lambda res=result: self._on_success(label, res))
            except Exception as e:
                self.after(0, lambda err=e: self._on_error(label, err))

        threading.Thread(target=worker, daemon=True).start()

    def _on_success(self, label: str, result):
        self._set_status("Ready.")
        if isinstance(result, str):
            self._append(result)
        else:
            self._append(str(result))

    def _on_error(self, label: str, err: Exception):
        self._set_status("Ready.")
        self._append(f"[ERROR] {label}: {err}")
        messagebox.showerror("Error", f"{label} failed:\n\n{err}")

    # ---------- Actions ----------
    def on_verify(self):
        def do():
            cf = self._get_client()
            data = cf.verify_token()
            status = data["result"].get("status", "unknown")
            name = data["result"].get("name", "")
            return f"Token status: {status}\nToken name: {name}"

        self._run_bg("Verify Token", do)

    def on_list_accounts(self):
        def do():
            cf = self._get_client()
            data = cf.list_accounts()
            self.accounts = data["result"]
            if not self.accounts:
                return "No accounts returned."

            # Update combobox display labels
            labels = [f"{a['name']}  ({a['id']})" for a in self.accounts]
            self.after(0, lambda: self.account_combo.config(values=labels))
            self.after(0, lambda: self.account_combo.current(0))
            self.after(0, lambda: self._select_account_by_index(0))

            out_lines = ["Accounts:"]
            for a in self.accounts:
                out_lines.append(f"- {a['name']} | id={a['id']}")
            return "\n".join(out_lines)

        self._run_bg("List Accounts", do)

    def _select_account_by_index(self, idx: int):
        if not self.accounts:
            return
        self.selected_account_id.set(self.accounts[idx]["id"])
        self._append(f"Selected account_id = {self.selected_account_id.get()}")

    def _on_account_selected(self, _event):
        idx = self.account_combo.current()
        if idx >= 0:
            self._select_account_by_index(idx)

    def on_list_members(self):
        def do():
            account_id = self.selected_account_id.get().strip()
            if not account_id:
                raise ValueError("List accounts and select an account first.")
            cf = self._get_client()
            data = cf.list_members(account_id)
            members = data["result"]
            if not members:
                return "No members returned."

            out_lines = ["Members:"]
            for m in members:
                user = m.get("user", {})
                out_lines.append(
                    f"- {user.get('email','(no email)')} | status={m.get('status')} | member_id={m.get('id')}"
                )
            return "\n".join(out_lines)

        self._run_bg("List Members", do)

    def on_list_groups(self):
        def do():
            account_id = self.selected_account_id.get().strip()
            if not account_id:
                raise ValueError("List accounts and select an account first.")
            cf = self._get_client()
            data = cf.list_user_groups(account_id)
            groups = data["result"]
            if not groups:
                return "No IAM user groups returned (or none exist)."

            out_lines = ["IAM User Groups:"]
            for g in groups:
                out_lines.append(f"- {g.get('name')} | id={g.get('id')}")
            return "\n".join(out_lines)

        self._run_bg("List IAM User Groups", do)


if __name__ == "__main__":
    try:
        App().mainloop()
    except Exception as e:
        messagebox.showerror("Fatal error", str(e))


