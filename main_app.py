# Cloudflare IAM Explorer
# main app

import threading
import tkinter as tk
from tkinter import messagebox, simpledialog
import customtkinter as ctk
import time
from requests.exceptions import ConnectionError, Timeout
from typing import Optional
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

        # cache:
        self._group_members_cache = {}  # group_id -> (timestamp, members_list)

        self._group_members_ttl = 60  # seconds

        # role cache:
        self.roles = []
        self.role_name_to_id = {}
        self.role_id_to_name = {}

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

        ctk.CTkButton(btns, text="Create User Group", command=self.create_group,
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
        preference = {
            "verify": ["Account Read", "Account Edit", "Group Read", "Group Edit"],
            "accounts": ["Account Read", "Account Edit"],

            "members_read": ["Account Read", "Account Edit"],
            "members_edit": ["Account Edit"],

            "groups_read": ["Group Read", "Group Edit", "Account Read", "Account Edit"],
            "groups_edit": ["Group Edit"],
        }

        for token_type in preference.get(purpose, []):
            tok = self.tokens[token_type].get().strip()
            if tok:
                return tok

        raise ValueError(f"Missing token for {purpose}. Open 'Manage Tokens' to save it.")

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

            left = ctk.CTkFrame(top, fg_color="transparent")
            left.pack(side="left", fill="x", expand=True)

            ctk.CTkLabel(left, text=email, text_color="#ffffff", font=("Segoe UI", 13, "bold")).pack(anchor="w")
            ctk.CTkLabel(left, text=status, text_color="#4ec9b0", font=("Segoe UI", 11)).pack(anchor="w")

            action_var = tk.StringVar(value="Actions")
            action_combo = ctk.CTkComboBox(
                top,
                variable=action_var,
                values=["Actions", "Edit Roles", "Remove Member"],
                state="readonly",
                width=150,
                fg_color="#1a1a1a",
                button_color="#444444",
                button_hover_color="#555555",
                border_color="#333333",
                text_color="#ffffff",
            )
            action_combo.pack(side="right")

            action_combo.configure(
                command=lambda choice, _mid=member_id, _email=email:
                self._handle_member_action(choice, _mid, _email)
            )

            ctk.CTkLabel(card, text=f"Member ID: {member_id}", text_color="#a0a0a0",
                         font=("Segoe UI", 11)).pack(anchor="w", padx=12, pady=(0, 2))

            ctk.CTkLabel(card, text=f"Roles: {roles_text}", text_color="#a0a0a0",
                         font=("Segoe UI", 11)).pack(anchor="w", padx=12, pady=(0, 10))

    def _load_group_members_async(self, group_id: str, label_widget):
        account_id = self.selected_account_id.get().strip()
        if not account_id or not group_id:
            return

        # cache
        now = time.time()
        cached = self._group_members_cache.get(group_id)
        if cached:
            ts, members = cached
            if now - ts < self._group_members_ttl:
                label_widget.configure(text=f"Users: {self._format_members_inline(members)}")
                return

        def worker():
            try:
                cf = self._client_for("groups_read")
                resp = cf.list_user_group_members(account_id, group_id)
                members = resp.get("result") or []

                self._group_members_cache[group_id] = (time.time(), members)

                text = f"Users: {self._format_members_inline(members)}"
                self.after(0, lambda t=text: label_widget.configure(text=t))
            except Exception as e:
                self.after(0, lambda err=e: label_widget.configure(
                    text=f"Users: (error: {str(err)[:80]})"
                ))

        threading.Thread(target=worker, daemon=True).start()

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

            action_var = tk.StringVar(value="Actions")
            action_combo = ctk.CTkComboBox(
                top,
                variable=action_var,
                values=["Actions", "Rename Group", "Add Member", "Remove Group"],
                state="readonly",
                width=150,
                fg_color="#1a1a1a",
                button_color="#444444",
                button_hover_color="#555555",
                border_color="#333333",
                text_color="#ffffff",
            )
            action_combo.pack(side="right")

            action_combo.configure(
                command=lambda choice, _gid=gid, _nl=name_label, _card=card:
                self._handle_group_action(choice, _gid, _nl, _card)
            )

            ctk.CTkLabel(card, text=f"Group ID: {gid}", text_color="#a0a0a0", font=("Segoe UI", 11)).pack(
                anchor="w", padx=12, pady=(0, 4)
            )

            members_label = ctk.CTkLabel(
                card,
                text="Users: (loading...)",
                text_color="#a0a0a0",
                font=("Segoe UI", 11),
                wraplength=900,
                justify="left"
            )
            members_label.pack(anchor="w", padx=12, pady=(0, 10))

            self._load_group_members_async(gid, members_label)

    def _handle_member_action(self, choice: str, member_id: str, email: str):
        if choice == "Actions":
            return

        if choice == "Edit Roles":
            self._edit_member_roles_for(member_id)
        elif choice == "Remove Member":
            self._remove_member(member_id, email)

    def _edit_member_roles_for(self, member_id: str) -> Optional[list[str]]:
        account_id = self.selected_account_id.get().strip()
        if not account_id:
            messagebox.showerror("Error", "Select an account first.", parent=self)
            return

        try:
            cf = self._client_for("members_read")

            # Load all roles if needed
            if not self.role_name_to_id:
                data = cf.list_roles(account_id)
                self.roles = data["result"]
                self.role_name_to_id = {r["name"]: r["id"] for r in self.roles}
                self.role_id_to_name = {r["id"]: r["name"] for r in self.roles}

            # Load this member so we can pre-select current roles
            member = cf.get_member(account_id, member_id)["result"]
            current_role_ids = {r.get("id") for r in (member.get("roles") or []) if r.get("id")}
            email = (member.get("user") or {}).get("email", "(unknown)")
        except Exception as e:
            messagebox.showerror("Error", f"Could not load roles/member details:\n\n{e}", parent=self)
            return

        picked_roles = self._pick_roles_dialog(
            self.roles,
            selected_role_ids=current_role_ids,
            title=f"Edit Roles for {email}"
        )

        if picked_roles is None:
            return

        final_role_ids: list[str] = list(picked_roles)

        def do():
            cf2 = self._client_for("members_edit")
            cf2.update_member_roles(account_id, member_id, final_role_ids)

            fresh = cf2.get_member(account_id, member_id)["result"]
            fresh_role_names = [r.get("name") for r in (fresh.get("roles") or [])]

            self.after(0, self.refresh_now)
            return f"Updated {email}\nCloudflare saved: {fresh_role_names}"

        self._run_bg("Edit Member Roles", do)

    def _remove_member(self, member_id: str, email: str):
        if not messagebox.askyesno("Remove Member", f"Remove {email} from this account?"):
            return

        def do():
            account_id = self.selected_account_id.get().strip()
            if not account_id:
                raise ValueError("Select an account first.")

            cf = self._client_for("members_edit")
            cf.delete_member(account_id, member_id)

            self.after(0, self.refresh_now)
            return f"Removed member: {email}"

        self._run_bg("Remove Member", do)

    def _handle_group_action(self, choice: str, group_id: str, name_label, card):
        if choice == "Actions":
            return
        if choice == "Rename Group":
            self._rename_group(group_id, name_label)
        elif choice == "Add Member":
            self._add_member_to_group(group_id)
        elif choice == "Remove Group":
            self._delete_group(group_id, card)

    def _add_member_to_group(self, group_id: str):
        account_id = self.selected_account_id.get().strip()
        if not account_id:
            messagebox.showerror("Error", "Select an account first.", parent=self)
            return

        # Use account token because we're listing account members
        try:
            cf_members = self._client_for("members_read")
            members = cf_members.list_members(account_id).get("result") or []
        except Exception as e:
            messagebox.showerror("Error", f"Could not load members:\n\n{e}", parent=self)
            return

        selected_member = self._pick_member_dialog(members, title="Add Member to Group")
        if not selected_member:
            return

        member_id = (selected_member.get("id") or "").strip()
        user = selected_member.get("user") or {}
        email = user.get("email", "(unknown)")

        def do():
            cf = self._client_for("groups_edit")
            cf.add_members_to_user_group(account_id, group_id, [member_id])

            self._group_members_cache.pop(group_id, None)
            self.after(0, self.refresh_now)
            return f"Added {email} to group {group_id}"

        self._run_bg("Add Member To Group", do)

    def _pick_member_dialog(self, members, title="Select Member") -> Optional[dict]:
        """
        Show a simple modal picker for account members.
        Returns the selected member dict or None.
        """
        if not members:
            messagebox.showinfo("No Members", "No account members are available to choose from.", parent=self)
            return None

        dialog = ctk.CTkToplevel(self)
        dialog.title(title)
        dialog.geometry("520x420")
        dialog.transient(self)
        dialog.grab_set()

        dialog.configure(fg_color="#000000")

        ctk.CTkLabel(
            dialog,
            text=title,
            text_color="#ffffff",
            font=("Segoe UI", 18, "bold")
        ).pack(anchor="w", padx=16, pady=(16, 8))

        selected = {"value": None}

        scroll = ctk.CTkScrollableFrame(dialog, fg_color="#000000")
        scroll.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        for m in members:
            user = m.get("user") or {}
            email = user.get("email", "(no email)")
            member_id = m.get("id", "")
            status = m.get("status", "")

            row = ctk.CTkFrame(scroll, fg_color="#111111", corner_radius=8)
            row.pack(fill="x", padx=4, pady=4)

            text = f"{email}\nstatus={status} | id={member_id}"
            btn = ctk.CTkButton(
                row,
                text=text,
                anchor="w",
                height=54,
                fg_color="#1a1a1a",
                hover_color="#2a2a2a",
                text_color="#ffffff",
                command=lambda member=m: _select(member)
            )
            btn.pack(fill="x", padx=8, pady=8)

        def _select(member):
            selected["value"] = member
            dialog.destroy()

        dialog.wait_window()
        return selected["value"]

    def _pick_roles_dialog(self, all_roles, selected_role_ids=None, title="Select Roles"):
        """
        all_roles: list of role dicts from Cloudflare
        selected_role_ids: set/list of currently assigned role IDs
        returns: list[str] of selected role IDs, or None if cancelled
        """
        selected_role_ids = set(selected_role_ids or [])

        dialog = ctk.CTkToplevel(self)
        dialog.title(title)
        dialog.geometry("560x500")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(fg_color="#000000")

        result = {"value": None}

        ctk.CTkLabel(
            dialog,
            text=title,
            text_color="#ffffff",
            font=("Segoe UI", 18, "bold")
        ).pack(anchor="w", padx=16, pady=(16, 8))

        scroll = ctk.CTkScrollableFrame(dialog, fg_color="#000000")
        scroll.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        role_vars = {}

        for role in sorted(all_roles, key=lambda r: r.get("name", "").lower()):
            role_id = role.get("id", "")
            role_name = role.get("name", "(unnamed role)")

            var = tk.BooleanVar(value=(role_id in selected_role_ids))
            role_vars[role_id] = var

            row = ctk.CTkFrame(scroll, fg_color="#111111", corner_radius=8)
            row.pack(fill="x", padx=4, pady=4)

            cb = ctk.CTkCheckBox(
                row,
                text=role_name,
                variable=var,
                onvalue=True,
                offvalue=False,
                text_color="#ffffff",
                fg_color="#0078d4",
                hover_color="#106ebe"
            )
            cb.pack(anchor="w", padx=10, pady=10)

        btns = ctk.CTkFrame(dialog, fg_color="#000000")
        btns.pack(fill="x", padx=16, pady=(0, 16))

        def on_save():
            chosen = [role_id for role_id, var in role_vars.items() if var.get()]
            result["value"] = chosen
            dialog.destroy()

        def on_cancel():
            result["value"] = None
            dialog.destroy()

        ctk.CTkButton(
            btns,
            text="Save",
            command=on_save,
            fg_color="#0078d4",
            hover_color="#106ebe",
            width=120
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btns,
            text="Cancel",
            command=on_cancel,
            fg_color="#333333",
            hover_color="#444444",
            width=120
        ).pack(side="left")

        dialog.wait_window()
        return result["value"]



    def _rename_group(self, group_id: str, name_label):
        new_name = simpledialog.askstring("Rename Group", "Enter new group name:", parent=self)
        if not new_name:
            return

        def do():
            account_id = self.selected_account_id.get().strip()
            cf = self._client_for("groups_edit")
            result = cf.update_user_group(account_id, group_id, new_name)["result"]
            final_name = result.get("name", new_name)

            self.after(0, lambda n=final_name: name_label.configure(text=n))
            return f"Renamed group to: {final_name}"

        self._run_bg("Rename Group", do)

    def _delete_group(self, group_id: str, card):
        if not messagebox.askyesno("Delete Group", "Delete this group?"):
            return

        def do():
            account_id = self.selected_account_id.get().strip()
            cf = self._client_for("groups_edit")
            cf.delete_user_group(account_id, group_id)

            self.after(0, card.destroy)
            return f"Deleted group: {group_id}"

        self._run_bg("Delete Group", do)

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
        email = simpledialog.askstring("Add Member", "Enter member email:", parent=self)
        if not email:
            return

        role_input = simpledialog.askstring(
            "Member Roles",
            "Enter roles (comma-separated).\nUse role names or role IDs:",
            parent=self
        )
        if not role_input:
            return

        tokens = [x.strip() for x in role_input.split(",") if x.strip()]

        def do():
            account_id = self.selected_account_id.get().strip()
            if not account_id:
                raise ValueError("Select an account first.")

            cf = self._client_for("members_edit")

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
                elif len(t) >= 20:
                    role_ids.append(t)
                else:
                    unknown.append(t)

            if unknown:
                raise ValueError(f"Unknown role names: {unknown}")

            result = cf.add_member(account_id, email, role_ids)
            self.after(0, self.refresh_now)
            return f"Added member: {email}\nResponse: {result.get('result')}"

        self._run_bg("Add Member", do)

    def create_group(self):
        group_name = simpledialog.askstring("Create Group", "Enter group name:", parent=self)
        if not group_name:
            return

        def do():
            account_id = self.selected_account_id.get().strip()
            if not account_id:
                raise ValueError("Select an account first.")

            cf = self._client_for("groups_edit")
            result = cf.create_user_group(account_id, group_name)["result"]

            self._group_members_cache.clear()
            self.after(0, self.refresh_now)
            return f"Created group: {result.get('name', group_name)}"

        self._run_bg("Create Group", do)

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

            members = self._client_for("members_read").list_members(account_id).get("result") or []
            groups = self._client_for("groups_read").list_user_groups(account_id).get("result") or []

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
            _ = self._token_for("members_read")
            _ = self._token_for("groups_read")
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
                members = self._client_for("members_read").list_members(account_id).get("result") or []
                self.after(0, lambda m=members: self._render_members_cards(m))
            except Exception as e:
                if self._is_network_error(e):
                    network_failed = True
                self.after(0, lambda err=e: self._append(f"[AUTO-REFRESH ERROR][members] {repr(err)}"))

            # GROUPS:
            try:
                groups = self._client_for("groups_read").list_user_groups(account_id).get("result") or []
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