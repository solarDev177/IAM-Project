# Test API token:

import threading
import tkinter as tk
from tkinter import ttk, messagebox
import requests

BASE_URL = "https://api.cloudflare.com/client/v4"


class CloudflareAPIError(RuntimeError):
    pass


class CloudflareClient:
    def __init__(self, token: str, timeout: int = 30):
        self.token = token.strip()
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        })

    def _request(self, method: str, path: str, params=None, json=None):
        url = f"{BASE_URL}{path}"
        resp = self.session.request(method, url, params=params, json=json, timeout=self.timeout)

        try:
            data = resp.json()
        except ValueError:
            raise CloudflareAPIError(f"Non-JSON response ({resp.status_code}): {resp.text[:200]}")

        # Cloudflare returns { success, errors, messages, result, result_info }
        if not resp.ok or not data.get("success", False):
            raise CloudflareAPIError(
                f"HTTP {resp.status_code} {path}\n"
                f"errors={data.get('errors')}\nmessages={data.get('messages')}"
            )
        return data


    def verify_token(self):
        ACCOUNT_ID = "3ef9aca3e663821dd1413c72b4ae0db8"
        return self._request("GET", f"/accounts/{ACCOUNT_ID}/tokens/verify")

    def list_accounts(self, page=1, per_page=50):
        return self._request("GET", "/accounts", params={"page": page, "per_page": per_page})

    def list_members(self, account_id: str, page=1, per_page=50):
        return self._request("GET", f"/accounts/{account_id}/members", params={"page": page, "per_page": per_page})

    def list_user_groups(self, account_id: str, page=1, per_page=50):
        return self._request("GET", f"/accounts/{account_id}/iam/user_groups",
                             params={"page": page, "per_page": per_page})


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cloudflare IAM Explorer (Tkinter)")
        self.geometry("980x620")

        self.tokens = {
            "Account Read": tk.StringVar(),
            "Account Edit": tk.StringVar(),
            "Group Read": tk.StringVar(),
            "Group Edit": tk.StringVar(),
        }
        self.selected_token_name = tk.StringVar(value="Account Read")

        self.accounts = []   # list of dicts from API
        self.selected_account_id = tk.StringVar(value="")

        self._build_ui()

    # ---------- UI ----------
    def _build_ui(self):
        top = ttk.Frame(self, padding=12)
        top.pack(fill="x")

        # Token selector
        ttk.Label(top, text="Token type:").grid(row=0, column=0, sticky="w")
        token_combo = ttk.Combobox(
            top,
            textvariable=self.selected_token_name,
            values=list(self.tokens.keys()),
            state="readonly",
            width=14
        )
        token_combo.grid(row=0, column=1, padx=(6, 12), sticky="w")
        token_combo.bind("<<ComboboxSelected>>", lambda e: self._refresh_token_entry())

        # Token entry
        ttk.Label(top, text="Token value:").grid(row=0, column=2, sticky="w")
        self.token_entry = ttk.Entry(top, width=78, show="•")
        self.token_entry.grid(row=0, column=3, sticky="we", padx=(6, 0))

        self.show_token = tk.BooleanVar(value=False)
        show_cb = ttk.Checkbutton(top, text="Show", variable=self.show_token, command=self._toggle_show)
        show_cb.grid(row=0, column=4, padx=(8, 0))

        # Buttons row
        btns = ttk.Frame(top)
        btns.grid(row=1, column=0, columnspan=5, sticky="w", pady=(10, 0))

        ttk.Button(btns, text="Verify Token", command=self.on_verify).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="List Accounts", command=self.on_list_accounts).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="List Members", command=self.on_list_members).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="List IAM User Groups", command=self.on_list_groups).pack(side="left")

        top.columnconfigure(3, weight=1)

        # Account picker
        mid = ttk.Frame(self, padding=(12, 0, 12, 12))
        mid.pack(fill="x")

        ttk.Label(mid, text="Selected account:").grid(row=0, column=0, sticky="w")
        self.account_combo = ttk.Combobox(mid, values=[], state="readonly", width=60)
        self.account_combo.grid(row=0, column=1, padx=(6, 12), sticky="w")
        self.account_combo.bind("<<ComboboxSelected>>", self._on_account_selected)

        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(mid, textvariable=self.status_var).grid(row=0, column=2, sticky="w")

        # Output area
        body = ttk.Frame(self, padding=12)
        body.pack(fill="both", expand=True)

        ttk.Label(body, text="Output:").pack(anchor="w")
        self.output = tk.Text(body, wrap="none")
        self.output.pack(fill="both", expand=True, pady=(6, 0))

        # scrollbar
        yscroll = ttk.Scrollbar(self.output, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side="right", fill="y")

        # Initialize entry with selected token var
        self._refresh_token_entry()

    def _toggle_show(self):
        self.token_entry.config(show="" if self.show_token.get() else "•")

    def _refresh_token_entry(self):
        # Save current entry into its token var before switching
        current_name = self.selected_token_name.get()
        for name, var in self.tokens.items():
            if name == current_name:
                var.set(self.token_entry.get().strip())

        # Load selected token into entry
        token = self.tokens[self.selected_token_name.get()].get()
        self.token_entry.delete(0, tk.END)
        self.token_entry.insert(0, token)

    def _set_status(self, text: str):
        self.status_var.set(text)

    def _append(self, text: str):
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)

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

    # When the process fails:
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

