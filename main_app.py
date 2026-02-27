# Cloudflare IAM Explorer
# main app

import threading
import tkinter as tk
from tkinter import messagebox, simpledialog
import customtkinter as ctk
import time
import requests
from requests.exceptions import ConnectionError, Timeout
from cloudflare_client import CloudflareClient
from token_manager import TokenManagerWindow
from token_store import TokenStore


class App(ctk.CTkToplevel):
    def __init__(self, master, account_id: str):
        super().__init__(master)
        self.title("Cloudflare IAM Explorer")
        self.geometry("1050x720")

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.configure(fg_color="#000000")

        # Core state
        self.initial_account_id = account_id
        self.selected_account_id = tk.StringVar(value=account_id)

        # Token store + tokens
        self.store = TokenStore()
        self.saved_tokens = self.store.load()
        self.tokens = {
            "Account Read": tk.StringVar(value=self.saved_tokens.get("Account Read", "")),
            "Account Edit": tk.StringVar(value=self.saved_tokens.get("Account Edit", "")),
            "Group Read": tk.StringVar(value=self.saved_tokens.get("Group Read", "")),
            "Group Edit": tk.StringVar(value=self.saved_tokens.get("Group Edit", "")),
        }
        self.selected_token_name = tk.StringVar(value="Account Read")

        # Accounts list (optional)
        self.accounts = []

        # Auto-refresh
        self._refresh_interval_ms = 60_000
        self._refresh_inflight = False
        self._refresh_job = None
        self._last_groups_error = None
        self._last_members_error = None

        # Timeout:
        self._net_failures = 0
        self._max_backoff_ms = 120_000  # cap at 2 minutes

        self._build_ui()

        # Start auto-refresh
        self.after(500, lambda: self.start_auto_refresh(self._refresh_interval_ms))
        self._last_groups_error = None

        # Stop refresh on close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------------- UI ----------------
    def _build_ui(self):
        # Top bar
        top = ctk.CTkFrame(self, fg_color="#000000")
        top.pack(fill="x", padx=12, pady=(12, 6))

        ctk.CTkLabel(top, text="Token type:", text_color="#ffffff").grid(row=0, column=0, sticky="w", padx=(0, 6))

        self.token_combo = ctk.CTkComboBox(
            top,
            variable=self.selected_token_name,
            values=list(self.tokens.keys()),
            state="readonly",
            width=150,
            fg_color="#1a1a1a",
            button_color="#0078d4",
            button_hover_color="#106ebe",
            border_color="#333333",
            command=self._on_token_type_change,   # receives selected string
        )
        self.token_combo.grid(row=0, column=1, sticky="w", padx=(0, 12))

        ctk.CTkLabel(top, text="Token value:", text_color="#ffffff").grid(row=0, column=2, sticky="w", padx=(0, 6))

        self.token_entry = ctk.CTkEntry(
            top,
            width=560,
            show="•",
            fg_color="#1a1a1a",
            border_color="#333333",
            text_color="#ffffff",
        )
        self.token_entry.grid(row=0, column=3, sticky="we", padx=(0, 6))

        self.show_token = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            top,
            text="Show",
            variable=self.show_token,
            command=self._toggle_show,
            width=80,
            fg_color="#0078d4",
            hover_color="#106ebe",
            text_color="#ffffff",
        ).grid(row=0, column=4, padx=(8, 0), sticky="w")

        top.columnconfigure(3, weight=1)

        # Buttons row
        btns = ctk.CTkFrame(self, fg_color="#000000")
        btns.pack(fill="x", padx=12, pady=(0, 10))

        ctk.CTkButton(btns, text="Verify Token", command=self.on_verify,
                      fg_color="#0078d4", hover_color="#106ebe").pack(side="left", padx=(0, 8))

        ctk.CTkButton(btns, text="List Accounts", command=self.on_list_accounts,
                      fg_color="#0078d4", hover_color="#106ebe").pack(side="left", padx=(0, 8))

        ctk.CTkButton(btns, text="Add Member", command=self.add_member,
                      fg_color="#0078d4", hover_color="#106ebe").pack(side="left", padx=(0, 8))

        ctk.CTkButton(btns, text="List Roles", command=self.on_list_roles,
                      fg_color="#0078d4", hover_color="#106ebe").pack(side="left", padx=(0, 8))

        ctk.CTkButton(btns, text="Edit Member Roles", command=self.on_edit_member_roles,
                      fg_color="#0078d4", hover_color="#106ebe").pack(side="left", padx=(0, 8))

        ctk.CTkButton(btns, text="Refresh Now", command=self.refresh_now,
                      fg_color="#0078d4", hover_color="#106ebe").pack(side="left", padx=(0, 8))

        ctk.CTkButton(btns, text="Manage Tokens", command=self.open_token_manager,
                      fg_color="#333333", hover_color="#444444").pack(side="left", padx=(8, 0))

        # Account chooser + status
        mid = ctk.CTkFrame(self, fg_color="#000000")
        mid.pack(fill="x", padx=12, pady=(0, 10))

        ctk.CTkLabel(mid, text="Selected account:", text_color="#ffffff").grid(row=0, column=0, sticky="w", padx=(0, 6))

        self.account_combo = ctk.CTkComboBox(
            mid,
            values=[f"Selected ({self.initial_account_id})"],
            state="readonly",
            width=520,
            fg_color="#1a1a1a",
            button_color="#0078d4",
            button_hover_color="#106ebe",
            border_color="#333333",
            command=lambda _: self._on_account_selected(),
        )
        self.account_combo.grid(row=0, column=1, sticky="w", padx=(0, 12))
        self.account_combo.set(f"Selected ({self.initial_account_id})")

        self.status_var = tk.StringVar(value="Ready.")
        ctk.CTkLabel(mid, textvariable=self.status_var, text_color="#4ec9b0").grid(row=0, column=2, sticky="w")

        # Tabs for Members / Groups
        live = ctk.CTkFrame(self, fg_color="#000000")
        live.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self.tabs = ctk.CTkTabview(live, fg_color="#000000")
        self.tabs.pack(fill="both", expand=True)

        members_tab = self.tabs.add("Members")
        groups_tab = self.tabs.add("User Groups")

        self.members_list = ctk.CTkScrollableFrame(members_tab, fg_color="#000000")
        self.members_list.pack(fill="both", expand=True, padx=10, pady=10)

        self.groups_list = ctk.CTkScrollableFrame(groups_tab, fg_color="#000000")
        self.groups_list.pack(fill="both", expand=True, padx=10, pady=10)

        # Optional output log (small)
        bottom = ctk.CTkFrame(self, fg_color="#000000")
        bottom.pack(fill="x", padx=12, pady=(0, 12))

        ctk.CTkLabel(bottom, text="Log:", text_color="#ffffff").pack(anchor="w")
        self.output = ctk.CTkTextbox(
            bottom, height=120, wrap="none",
            fg_color="#1a1a1a", border_color="#333333", text_color="#ffffff"
        )
        self.output.pack(fill="x", expand=False, pady=(6, 0))

        # Initialize token display
        self._load_selected_token_into_entry()

    # ---------------- UI helpers ----------------
    def _set_status(self, text: str):
        self.status_var.set(text)

    def _append(self, text: str):
        self.output.insert("end", text + "\n")
        self.output.see("end")

    def _toggle_show(self):
        self.token_entry.configure(show="" if self.show_token.get() else "•")

    def _load_selected_token_into_entry(self):
        token_type = self.selected_token_name.get()
        token = self.tokens[token_type].get().strip()

        self.token_entry.configure(state="normal")
        self.token_entry.delete(0, "end")
        self.token_entry.insert(0, token)
        self.token_entry.configure(state="normal")  # keep display-only

    def _on_token_type_change(self, choice: str):
        # choice is the selected token type string
        self.selected_token_name.set(choice)
        self._load_selected_token_into_entry()

    def _on_account_selected(self):
        selection = self.account_combo.get().strip()
        # Expect: "Name  (ACCOUNT_ID)" OR "Selected (ACCOUNT_ID)"
        if "(" in selection and selection.endswith(")"):
            account_id = selection.split("(")[-1][:-1].strip()
            if len(account_id) == 32:
                self.selected_account_id.set(account_id)
                self._append(f"Selected account_id = {account_id}")

    # ---------------- Token selection per action ----------------
    def _token_for(self, purpose: str) -> str:
        """
        Pick a token based on what endpoint you're calling.
        Prevents 403 when using group token for member endpoints.
        """
        preference = {
            "verify": ["Account Read", "Account Edit", "Group Read", "Group Edit"],
            "accounts": ["Account Read", "Account Edit"],
            "members": ["Account Read", "Account Edit"],
            # Allow account token fallback for groups:
            "groups": ["Group Read", "Group Edit", "Account Read", "Account Edit"],
        }
        for token_type in preference.get(purpose, []):
            tok = self.tokens[token_type].get().strip()
            if tok:
                return tok
        raise ValueError(f"Missing token for {purpose}. Open 'Manage Tokens' to save it.")

    def _fetch_user_groups_with_fallback(self, account_id: str):
        token_order = ["Group Read", "Group Edit", "Account Read", "Account Edit"]
        last_err = None

        for token_type in token_order:
            tok = self.tokens[token_type].get().strip()
            if not tok:
                continue
            try:
                cf = CloudflareClient(tok)
                return cf.list_user_groups(account_id).get("result") or []
            except Exception as e:
                last_err = e
                # Only fall back on permission errors:
                if "HTTP 403" in str(e) or "Authentication error" in str(e):
                    continue
                raise  # other errors should surface immediately

        raise last_err or ValueError("No token available for user groups.")

    def _client_for(self, purpose: str) -> CloudflareClient:
        token = self._token_for(purpose)
        return CloudflareClient(token)

    def _get_client(self) -> CloudflareClient:
        token = self.token_entry.get().strip()
        if not token:
            raise ValueError("Please paste a token first, or use 'Manage Tokens'.")
        return CloudflareClient(token)

    # ---------------- Background runner ----------------
    def _run_bg(self, label: str, func):
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
        if result is not None:
            self._append(str(result))

    def _on_error(self, label: str, err: Exception):
        self._set_status("Ready.")
        self._append(f"[ERROR] {label}: {err}")
        messagebox.showerror("Error", f"{label} failed:\n\n{err}")

    # ---------------- Rendering: CTk "cards" ----------------
    @staticmethod
    def _clear_children(widget):
        for child in widget.winfo_children():
            child.destroy()

    def _render_members_cards(self, members):
        self._clear_children(self.members_list)

        if not members:
            ctk.CTkLabel(self.members_list, text="No members found.", text_color="#a0a0a0").pack(anchor="w", pady=6)
            return

        for m in members:
            user = m.get("user") or {}
            email = user.get("email", "(no email)")
            status = m.get("status", "")
            member_id = m.get("id", "")

            roles = m.get("roles") or []
            role_names = [r.get("name", "") for r in roles if isinstance(r, dict)]
            roles_text = ", ".join([r for r in role_names if r]) or "(no roles)"

            card = ctk.CTkFrame(self.members_list, fg_color="#111111", corner_radius=10)
            card.pack(fill="x", padx=6, pady=6)

            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=12, pady=(10, 2))

            ctk.CTkLabel(top, text=email, text_color="#ffffff", font=("Segoe UI", 13, "bold")).pack(side="left")
            ctk.CTkLabel(top, text=status, text_color="#4ec9b0", font=("Segoe UI", 11)).pack(side="right")

            ctk.CTkLabel(card, text=f"Member ID: {member_id}", text_color="#a0a0a0",
                         font=("Segoe UI", 11)).pack(anchor="w", padx=12, pady=(0, 2))

            ctk.CTkLabel(card, text=f"Roles: {roles_text}", text_color="#a0a0a0",
                         font=("Segoe UI", 11)).pack(anchor="w", padx=12, pady=(0, 10))

    def _format_members_inline(self, members, empty_text="(no members)"):
        emails = []

        for m in members or []:
            if not isinstance(m, dict):
                continue

            if "email" in m:
                emails.append(m["email"])
            elif "user" in m and isinstance(m["user"], dict):
                email = m["user"].get("email")
                if email:
                    emails.append(email)

        return ", ".join(emails) or empty_text

    def _render_groups_cards(self, groups):
        self._clear_children(self.groups_list)

        if not groups:
            ctk.CTkLabel(self.groups_list, text="No user groups found.", text_color="#a0a0a0").pack(anchor="w", pady=6)
            return

        for g in groups:
            name = g.get("name", "(no name)")
            gid = g.get("id", "")

            card = ctk.CTkFrame(self.groups_list, fg_color="#111111", corner_radius=10)
            card.pack(fill="x", padx=6, pady=6)

            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=12, pady=(10, 2))

            name_label = ctk.CTkLabel(top, text=name, text_color="#ffffff", font=("Segoe UI", 13, "bold"))
            name_label.pack(side="left")

            action_var = tk.StringVar(value="Edit")
            action_combo = ctk.CTkComboBox(top, variable=action_var, values=["Rename", "Remove"], state="readonly",
                                           width=120, fg_color="#1a1a1a", button_color="#444444",
                                           button_hover_color="#555555", border_color="#333333", text_color="#ffffff",
                                           )

            action_combo.pack(side="right")
            action_combo.configure(
                command=lambda choice, _gid=gid, _nl=name_label, _card=card:
                self._rename_group(_gid, _nl)
                if choice == "Rename"
                else self._delete_group(_gid, _card)
            )

            ctk.CTkLabel(card, text=f"Group ID: {gid}", text_color="#a0a0a0", font=("Segoe UI", 11)).pack(anchor="w",
                                                                                                          padx=12,
                                                                                                          pady=(0, 4))

            try:
                resp = self.cf.list_user_group_members(self.account_id, gid)
                members = resp.get("result", [])
            except Exception as e:
                print(f"[WARN] Group members not accessible: {name} ({gid}) → {e}")
                members = []

            members_text = self._format_members_inline(members)

            ctk.CTkLabel(card, text=f"Users: {members_text}", text_color="#a0a0a0", font=("Segoe UI", 11),
                         wraplength=520, justify="left").pack(anchor="w", padx=12, pady=(0, 10))

    def _is_network_error(self, err: Exception) -> bool:
        return isinstance(err, (ConnectionError, Timeout))

    def _next_backoff_ms(self) -> int:
        # 10s, 20s, 40s, 80s... capped
        return min(self._refresh_interval_ms * (2 ** self._net_failures), self._max_backoff_ms)

    # ---------------- Actions ----------------
    def on_verify(self):
        def do():
            account_id = self.selected_account_id.get().strip()
            if not account_id:
                raise ValueError("No account selected.")

            cf = self._client_for("verify")
            data = cf.verify_token_for_account(account_id)
            r = data.get("result") or {}

            return (
                f"Token status: {r.get('status', 'unknown')}\n"
                f"Token id: {r.get('id', '')}\n"
                f"Not before: {r.get('not_before', '')}\n"
                f"Expires on: {r.get('expires_on', '')}"
            )

        self._run_bg("Verify Token", do)

    def on_list_accounts(self):
        def do():
            cf = self._client_for("accounts")
            data = cf.list_accounts()
            self.accounts = data.get("result") or []
            if not self.accounts:
                return "No accounts returned."

            labels = [f"{a.get('name','(no name)')}  ({a.get('id','')})" for a in self.accounts]
            first_id = self.accounts[0].get("id", "")

            def update_ui():
                self.account_combo.configure(values=labels)
                self.account_combo.set(labels[0])
                self.selected_account_id.set(first_id)
                self._append(f"Selected account_id = {first_id}")

            self.after(0, update_ui)

            return f"Loaded {len(self.accounts)} accounts."

        self._run_bg("List Accounts", do)

    def add_member(self):

        def submit():
            val1 = entry1.get()
            val2 = entry2.get()
            messagebox.showinfo("Inputs", f"First: {val1}\nSecond: {val2}")
            root.destroy()

        # Create window
        root = tk.Tk()
        root.title("Two Inputs")

        # First input
        tk.Label(root, text="Enter :").grid(row=0, column=0, padx=5, pady=5)
        entry1 = tk.Entry(root)
        entry1.grid(row=0, column=1, padx=5, pady=5)

        # Second input
        tk.Label(root, text="Enter second value:").grid(row=1, column=0, padx=5, pady=5)
        entry2 = tk.Entry(root)
        entry2.grid(row=1, column=1, padx=5, pady=5)

        # Submit button
        tk.Button(root, text="Submit", command=submit).grid(row=2, columnspan=2, pady=10)

        def do():
            cf = self._client_for("members")

        self._run_bg("Add New Member", do)

    def on_list_roles(self):
        def do():
            account_id = self.selected_account_id.get().strip()
            if not account_id:
                raise ValueError("Select an account first.")
            cf = self._get_client()
            data = cf.list_roles(account_id)
            self.roles = data["result"]
            self.role_name_to_id = {r["name"]: r["id"] for r in self.roles}
            self.role_id_to_name = {r["id"]: r["name"] for r in self.roles}
            out = ["Roles:"]

            for r in self.roles:
                out.append(f"- {r['name']} | id={r['id']}")

            return "\n".join(out)

        self._run_bg("List Roles", do)

    def on_edit_member_roles(self):
        # --- IMPORTANT: dialogs must run on the MAIN/UI thread ---
        member_id = simpledialog.askstring("Member ID", "Enter member_id to update:", parent=self)
        if not member_id:
            return

        role_input = simpledialog.askstring(
            "Roles",
            "Enter roles (comma-separated).\nYou can use role NAMES (recommended) or role IDs:",
            parent=self
        )
        if not role_input:
            return

        member_id = member_id.strip()
        tokens = [x.strip() for x in role_input.split(",") if x.strip()]

        # --- network work runs in your background thread ---
        def do():
            account_id = self.selected_account_id.get().strip()
            if not account_id:
                raise ValueError("Select an account first.")

            cf = self._get_client()

            # Make sure roles are loaded
            if not self.role_name_to_id:
                data = cf.list_roles(account_id)
                self.roles = data["result"]
                self.role_name_to_id = {r["name"]: r["id"] for r in self.roles}
                self.role_id_to_name = {r["id"]: r["name"] for r in self.roles}

            role_ids = []
            unknown = []

            for t in tokens:
                if t in self.role_name_to_id:
                    role_ids.append(self.role_name_to_id[t])
                elif len(t) >= 20:  # rough check: likely an ID
                    role_ids.append(t)
                else:
                    unknown.append(t)

            if unknown:
                raise ValueError(f"Unknown role names: {unknown}\nClick 'List Roles' to see valid names.")

            # Perform update
            result = cf.update_member_roles(account_id, member_id, role_ids)["result"]
            email = (result.get("user") or {}).get("email", "(unknown)")
            role_names = [self.role_id_to_name.get(rid, rid) for rid in role_ids]

            # Immediately read back what Cloudflare actually saved
            fresh = cf.get_member(account_id, member_id)["result"]
            fresh_role_names = [r.get("name") for r in (fresh.get("roles") or [])]

            return (
                f"Updated {email} (member_id={member_id})\n"
                f"Requested roles: {role_names}\n"
                f"Cloudflare saved: {fresh_role_names}"
            )

        self._run_bg("Edit Member Roles", do)


    def refresh_now(self):
        """
        Manually refresh members and groups at the same time.
        """
        def do():
            account_id = self.selected_account_id.get().strip()
            if not account_id:
                raise ValueError("Select an account first.")

            members = self._client_for("members").list_members(account_id).get("result") or []
            groups = self._fetch_user_groups_with_fallback(account_id)

            # members/groups are lists (captured from the worker thread):

            self.after(0, self._render_members_cards, members)
            self.after(0, self._render_groups_cards, groups)

            # status/log:
            self.after(0, self._set_status, "Auto-refreshed.")
            self.after(0, self._append, f"Refreshed: {len(members)} members, {len(groups)} groups.")

            return f"Refreshed: {len(members)} members, {len(groups)} groups."

        self._run_bg("Refresh Now", do)

    # ---------------- Auto-refresh ----------------
    def start_auto_refresh(self, interval_ms=10_000):
        self._refresh_interval_ms = interval_ms
        self._schedule_refresh()

    def stop_auto_refresh(self):
        if self._refresh_job is not None:
            try:
                self.after_cancel(self._refresh_job)
            except Exception:
                pass
            self._refresh_job = None

    def _schedule_refresh(self, delay_ms=None):
        if delay_ms is None:
            delay_ms = self._refresh_interval_ms
        self._refresh_job = self.after(delay_ms, self._refresh_tick)

    def _refresh_tick(self):
        # don’t schedule the next one yet — do it after success/failure
        if self._refresh_inflight:
            self._schedule_refresh(self._refresh_interval_ms)
            return

        account_id = self.selected_account_id.get().strip()
        if not account_id:
            self._schedule_refresh(self._refresh_interval_ms)
            return

        try:
            _ = self._token_for("members")
            _ = self._token_for("groups")
        except Exception:
            self._schedule_refresh(self._refresh_interval_ms)
            return

        self._refresh_inflight = True
        threading.Thread(target=self._refresh_bg, daemon=True).start()

    def _refresh_bg(self):
        # Get the account IDs
        account_id = self.selected_account_id.get().strip()
        network_failed = False

        try:
            # MEMBERS:
            try:
                members = self._client_for("members").list_members(account_id).get("result") or []
                self.after(0, lambda m=members: self._render_members_cards(m))
            except Exception as e:
                if self._is_network_error(e):
                    network_failed = True
                self.after(0, lambda err=e: self._append(f"[AUTO-REFRESH ERROR][members] {repr(err)}"))

            # GROUPS:
            try:
                groups = self._client_for("groups").list_user_groups(account_id).get("result") or []
                self.after(0, lambda g=groups: self._render_groups_cards(g))
            except Exception as e:
                if self._is_network_error(e):
                    network_failed = True
                self.after(0, lambda err=e: self._append(f"[AUTO-REFRESH ERROR][groups] {repr(err)}"))

        finally:
            def finalize():
                # Stop refreshing and check if network_failed:
                self._refresh_inflight = False
                if network_failed:
                    self._net_failures += 1
                    wait = self._next_backoff_ms()
                    self._set_status(f"Network issue — retrying in {wait // 1000}s")
                    self._schedule_refresh(wait)
                else:
                    self._net_failures = 0
                    self._set_status("Auto-refreshed.")
                    self._schedule_refresh(self._refresh_interval_ms)

            self.after(0, finalize)

    # ---------------- Token Manager ----------------
    def open_token_manager(self):
        def on_saved(_tokens):
            # reload from disk
            self.saved_tokens = self.store.load()
            for k in self.tokens:
                self.tokens[k].set(self.saved_tokens.get(k, ""))

            self._load_selected_token_into_entry()
            self._append("Tokens reloaded from disk.")

        TokenManagerWindow(self, on_saved=on_saved)
    def _on_close(self):
        self.stop_auto_refresh()
        self.destroy()