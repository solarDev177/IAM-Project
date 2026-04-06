# Cloudflare IAM Explorer
# main app

import threading
import tkinter as tk
from tkinter import messagebox, simpledialog
import customtkinter as ctk
import time
import g4f

from decorator import EMPTY
from requests.exceptions import ConnectionError, Timeout
from typing import Optional, Callable, Any, Dict, List, Tuple

from cloudflare_client import CloudflareClient
from token_manager import TokenManagerWindow
from token_store import TokenStore


class App(ctk.CTkToplevel):
    def __init__(self, master, account_id: str):
        super().__init__(master)
        self.title("Cloudflare IAM Explorer")
        self.geometry("1920x1080")

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.configure(fg_color="#000000")

        # Core state
        self.initial_account_id = account_id
        self.selected_account_id = tk.StringVar(value=account_id)

        # Token store + tokens
        self.store = TokenStore()
        self.saved_tokens = self.store.load()
        self.tokens: Dict[str, tk.StringVar] = {
            "Account Read": tk.StringVar(value=self.saved_tokens.get("Account Read", "")),
            "Account Edit": tk.StringVar(value=self.saved_tokens.get("Account Edit", "")),
            "Group Read": tk.StringVar(value=self.saved_tokens.get("Group Read", "")),
            "Group Edit": tk.StringVar(value=self.saved_tokens.get("Group Edit", "")),
        }
        self.selected_token_name = tk.StringVar(value="Account Read")

        # Accounts list (optional)
        self.accounts: List[dict] = []

        # group members cache:
        self._group_members_ttl = 60  # seconds
        self._group_members_cache: Dict[str, Tuple[float, List[dict]]] = {}

        # role caches:
        self.roles: List[dict] = []
        self.role_name_to_id: Dict[str, str] = {}
        self.role_id_to_name: Dict[str, str] = {}

        # Auto-refresh
        self._refresh_interval_ms = 60_000
        self._refresh_inflight = False
        self._refresh_job = None
        self._last_groups_error = None
        self._last_members_error = None

        # Backoff:
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

        ctk.CTkLabel(top, text="Token type:", text_color="#ffffff").grid(
            row=0, column=0, sticky="w", padx=(0, 6)
        )

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
            command=self._on_token_type_change,
        )
        self.token_combo.grid(row=0, column=1, sticky="w", padx=(0, 12))

        ctk.CTkLabel(top, text="Token value:", text_color="#ffffff").grid(
            row=0, column=2, sticky="w", padx=(0, 6)
        )

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

        ctk.CTkButton(btns, text="Launch Scan", command=self._return_all_users_information,
                      fg_color="#333333", hover_color="#444444").pack(side="left", padx=(8, 0))

        # Account chooser + status
        mid = ctk.CTkFrame(self, fg_color="#000000")
        mid.pack(fill="x", padx=12, pady=(0, 10))

        ctk.CTkLabel(mid, text="Selected account:", text_color="#ffffff").grid(
            row=0, column=0, sticky="w", padx=(0, 6)
        )

        def on_account_choice(_choice: str):
            self._on_account_selected()

        self.account_combo = ctk.CTkComboBox(
            mid,
            values=[f"Selected ({self.initial_account_id})"],
            state="readonly",
            width=520,
            fg_color="#1a1a1a",
            button_color="#0078d4",
            button_hover_color="#106ebe",
            border_color="#333333",
            command=on_account_choice,
        )
        self.account_combo.grid(row=0, column=1, sticky="w", padx=(0, 12))
        self.account_combo.set(f"Selected ({self.initial_account_id})")

        self.status_var = tk.StringVar(value="Ready.")
        ctk.CTkLabel(mid, textvariable=self.status_var, text_color="#4ec9b0").grid(
            row=0, column=2, sticky="w"
        )

        # Tabs
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

        # Log
        bottom = ctk.CTkFrame(self, fg_color="#000000")
        bottom.pack(fill="x", padx=12, pady=(0, 12))

        ctk.CTkLabel(bottom, text="Log:", text_color="#ffffff").pack(anchor="w")
        self.output = ctk.CTkTextbox(
            bottom, height=120, wrap="none",
            fg_color="#1a1a1a", border_color="#333333", text_color="#ffffff"
        )
        self.output.pack(fill="x", expand=False, pady=(6, 0))

        self._load_selected_token_into_entry()

    # ---------------- UI helpers ----------------
    def _set_status(self, text: str):
        self.status_var.set(text)

    def _append(self, text: str):
        self.output.insert("end", text + "\n")
        self.output.see("end")

    def _ui(self, func: Callable[..., Any], /, *args: Any, **kwargs: Any) -> None:
        """Run a UI update safely on the Tk main thread."""
        if kwargs:
            def call() -> None:
                func(*args, **kwargs)
            self.after(0, call)
        elif args:
            self.after(0, func, *args)
        else:
            self.after(0, func)

    def _toggle_show(self):
        self.token_entry.configure(show="" if self.show_token.get() else "•")

    def _load_selected_token_into_entry(self):
        token_type = self.selected_token_name.get()
        token = self.tokens[token_type].get().strip()
        self.token_entry.configure(state="normal")
        self.token_entry.delete(0, "end")
        self.token_entry.insert(0, token)
        self.token_entry.configure(state="normal")

    def _on_token_type_change(self, choice: str):
        self.selected_token_name.set(choice)
        self._load_selected_token_into_entry()

    def _on_account_selected(self):
        selection = self.account_combo.get().strip()
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
        return CloudflareClient(self._token_for(purpose))

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
                self._ui(self._on_success, label, result)
            except Exception as e:
                self._ui(self._on_error, label, e)

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

    def _render_scan_results(self, parent, raw_text: str):
        # Split based on the User: tag that we implemented in the formatting when adding the users to a list.
        sections = raw_text.split("User:")
        for section in sections:
            section = section.strip()
            if not section:
                continue
            lines = [line.strip() for line in section.split("\n") if line.strip()]
            card = ctk.CTkFrame(parent, fg_color="#111111", corner_radius=10)
            card.pack(fill="x", padx=6, pady=6)

            # Sets the color of the email to bold.
            title = lines[0] if lines else "Unknown User"
            ctk.CTkLabel(
                card,
                text=title,
                text_color="#ffffff",
                font=("Segoe UI", 14, "bold")
            ).pack(anchor="w", padx=12, pady=(10, 4))

            # Rest of the cards coloring.
            for line in lines[1:]:
                color = "#ffffff"

                # Changes colors of the roles based on the risk
                if "Critical" in line:
                    color = "#ff4c4c"
                elif "High" in line:
                    color = "#ff914d"
                elif "Medium" in line:
                    color = "#ffd166"
                elif "Low" in line:
                    color = "#4ec9b0"

                ctk.CTkLabel(
                    card,
                    text=line,
                    text_color=color,
                    wraplength=800,
                    justify="left",
                    font=("Segoe UI", 11)
                ).pack(anchor="w", padx=12, pady=2)

            # For Spacing
            ctk.CTkLabel(card, text="").pack(pady=(0, 6))

    def _render_members_cards(self, members: List[dict]) -> None:
        self._clear_children(self.members_list)
        cf = self._client_for("groups_read")

        if not members:
            ctk.CTkLabel(self.members_list, text="No members found.", text_color="#a0a0a0").pack(
                anchor="w", pady=6
            )
            return

        for m in members:
            user = m.get("user") or {}
            email = user.get("email", "(no email)")
            status = m.get("status", "")
            member_id = m.get("id", "")
            account_id = self.selected_account_id.get().strip()

            if m.get("user_groups"):
                user_group_id = (m["user_groups"][0].get("id"))
                resp = cf.get_user_group(account_id, user_group_id)
                group_detail = resp.get("result") or {}
                permissions_text = ", " + self._format_group_permissions(group_detail)
                if permissions_text == "No permissions assigned":
                    permissions_text = ""

            roles = m.get("roles") or []
            role_names = [r.get("name", "") for r in roles if isinstance(r, dict)]
            roles_text = ", ".join([r for r in role_names if r]) or "(no roles)"
            roles_text += permissions_text

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

            def on_member_action(choice: str, _mid=member_id, _email=email):
                self._handle_member_action(choice, _mid, _email)

            action_combo.configure(command=on_member_action)

            ctk.CTkLabel(card, text=f"Member ID: {member_id}", text_color="#a0a0a0",
                         font=("Segoe UI", 11)).pack(anchor="w", padx=12, pady=(0, 2))

            ctk.CTkLabel(card, text=f"Roles: {roles_text}", text_color="#a0a0a0",
                         font=("Segoe UI", 11)).pack(anchor="w", padx=12, pady=(0, 10))

    def _load_group_members_async(self, group_id: str, label_widget: ctk.CTkLabel) -> None:
        account_id = self.selected_account_id.get().strip()
        if not account_id or not group_id:
            return

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
                self._ui(label_widget.configure, text=text)
            except Exception as e:
                self._ui(label_widget.configure, text=f"Users: (error: {str(e)[:80]})")

        threading.Thread(target=worker, daemon=True).start()

    def _format_members_inline(self, members, empty_text="(no members)"):
        emails: List[str] = []
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

    def _render_groups_cards(self, groups: List[dict]) -> None:
        self._clear_children(self.groups_list)

        if not groups:
            ctk.CTkLabel(
                self.groups_list,
                text="No user groups found.",
                text_color="#a0a0a0"
            ).pack(anchor="w", pady=6)
            return

        account_id = self.selected_account_id.get().strip()

        for g in groups:
            name = g.get("name", "(no name)")
            gid = g.get("id", "")

            card = ctk.CTkFrame(self.groups_list, fg_color="#111111", corner_radius=10)
            card.pack(fill="x", padx=6, pady=6)

            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=12, pady=(10, 2))

            left = ctk.CTkFrame(top, fg_color="transparent")
            left.pack(side="left", fill="x", expand=True)

            name_label = ctk.CTkLabel(
                left,
                text=name,
                text_color="#ffffff",
                font=("Segoe UI", 13, "bold")
            )
            name_label.pack(anchor="w")

            action_var = tk.StringVar(value="Actions")
            action_combo = ctk.CTkComboBox(
                top,
                variable=action_var,
                values=[
                    "Actions",
                    "Permission Policies",
                    "Rename Group",
                    "Add Member",
                    "Remove Member",
                    "Remove Group",
                ],
                state="readonly",
                width=170,
                fg_color="#1a1a1a",
                button_color="#444444",
                button_hover_color="#555555",
                border_color="#333333",
                text_color="#ffffff",
            )
            action_combo.pack(side="right")

            def on_group_action(choice: str, _gid=gid, _nl=name_label, _card=card):
                self._handle_group_action(choice, _gid, _nl, _card)

            action_combo.configure(command=on_group_action)

            ctk.CTkLabel(
                card,
                text=f"Group ID: {gid}",
                text_color="#a0a0a0",
                font=("Segoe UI", 11)
            ).pack(anchor="w", padx=12, pady=(0, 4))

            users_label = ctk.CTkLabel(
                card,
                text="Users: loading...",
                text_color="#a0a0a0",
                font=("Segoe UI", 11),
                wraplength=900,
                justify="left"
            )
            users_label.pack(anchor="w", padx=12, pady=(0, 4))

            permissions_label = ctk.CTkLabel(
                card,
                text="Permissions: loading...",
                text_color="#a0a0a0",
                font=("Segoe UI", 11),
                wraplength=900,
                justify="left"
            )
            permissions_label.pack(anchor="w", padx=12, pady=(0, 10))

            self._load_group_members_async(gid, users_label)
            self._load_group_permissions_async(account_id, gid, permissions_label)

    def _load_group_permissions_async(self, account_id: str, group_id: str, label_widget: ctk.CTkLabel) -> None:
        if not account_id or not group_id:
            label_widget.configure(text="Permissions: (unavailable)")
            return

        def worker():
            try:
                cf = self._client_for("groups_read")
                resp = cf.get_user_group(account_id, group_id)
                group_detail = resp.get("result") or {}

                permissions_text = self._format_group_permissions(group_detail)
                self._ui(label_widget.configure, text=f"Permissions: {permissions_text}")
            except Exception as e:
                self._ui(label_widget.configure, text=f"Permissions: (error: {str(e)[:80]})")

        threading.Thread(target=worker, daemon=True).start()

    # ---------------- Member actions ----------------
    def _handle_member_action(self, choice: str, member_id: str, email: str):
        if choice == "Actions":
            return
        if choice == "Edit Roles":
            self._edit_member_roles_for(member_id)
        elif choice == "Remove Member":
            self._remove_member(member_id, email)

    def _edit_member_roles_for(self, member_id: str) -> Optional[List[str]]:
        account_id = self.selected_account_id.get().strip()
        if not account_id:
            messagebox.showerror("Error", "Select an account first.", parent=self)
            return None

        try:
            cf = self._client_for("members_read")

            if not self.role_name_to_id:
                data = cf.list_roles(account_id)
                self.roles = data.get("result") or []
                self.role_name_to_id = {r["name"]: r["id"] for r in self.roles if r.get("name") and r.get("id")}
                self.role_id_to_name = {r["id"]: r["name"] for r in self.roles if r.get("name") and r.get("id")}

            member = cf.get_member(account_id, member_id)["result"]
            current_role_ids = {r.get("id") for r in (member.get("roles") or []) if r.get("id")}
            email = (member.get("user") or {}).get("email", "(unknown)")
        except Exception as e:
            messagebox.showerror("Error", f"Could not load roles/member details:\n\n{e}", parent=self)
            return None

        picked_roles = self._pick_roles_dialog(
            self.roles,
            selected_role_ids=current_role_ids,
            title=f"Edit Roles for {email}",
        )
        if picked_roles is None:
            return None

        final_role_ids: List[str] = picked_roles

        def do():
            if not final_role_ids:
                raise ValueError("Select at least one role. Cloudflare does not allow empty role assignments.")
            cf2 = self._client_for("members_edit")
            cf2.update_member_roles(account_id, member_id, final_role_ids)

            fresh = cf2.get_member(account_id, member_id)["result"]
            fresh_role_names = [r.get("name") for r in (fresh.get("roles") or [])]

            self._ui(self.refresh_now)
            return f"Updated {email}\nCloudflare saved: {fresh_role_names}"

        self._run_bg("Edit Member Roles", do)
        return final_role_ids

    def _remove_member(self, member_id: str, email: str):
        if not messagebox.askyesno("Remove Member", f"Remove {email} from this account?"):
            return

        def do():
            account_id = self.selected_account_id.get().strip()
            if not account_id:
                raise ValueError("Select an account first.")
            cf = self._client_for("members_edit")
            cf.delete_member(account_id, member_id)
            self._ui(self.refresh_now)
            return f"Removed member: {email}"

        self._run_bg("Remove Member", do)

    # ---------------- Group actions ----------------
    def _handle_group_action(self, choice: str, group_id: str, name_label, card):
        if choice == "Actions":
            return
        if choice == "Permission Policies":
            self._edit_group_permissions(group_id)
        elif choice == "Rename Group":
            self._rename_group(group_id, name_label)
        elif choice == "Add Member":
            self._add_member_to_group(group_id)
        elif choice == "Remove Member":
            self._remove_member_from_group(group_id)
        elif choice == "Remove Group":
            self._delete_group(group_id, card)

    # ----- Permission policies (from main_app.py) -----
    def _edit_group_permissions(self, group_id: str):
        account_id = self.selected_account_id.get().strip()
        if not account_id:
            messagebox.showerror("Error", "Select an account first.", parent=self)
            return

        def do_load():
            cf = self._client_for("groups_read")

            group = cf.get_user_group(account_id, group_id).get("result") or {}
            policies = group.get("policies") or []
            first = policies[0] if policies else {}

            existing_perm_ids = {pg.get("id") for pg in (first.get("permission_groups") or []) if pg.get("id")}
            existing_res_ids = [rg.get("id") for rg in (first.get("resource_groups") or []) if rg.get("id")]
            existing_res_id = existing_res_ids[0] if existing_res_ids else None
            access = first.get("access", "allow")

            # NOTE: these require CloudflareClient methods:
            # - list_permission_groups(account_id)
            # - list_resource_groups(account_id)
            perm_groups = cf.list_permission_groups(account_id).get("result") or []
            res_groups = cf.list_resource_groups(account_id).get("result") or []

            return group, access, existing_perm_ids, existing_res_id, perm_groups, res_groups

        def worker():
            try:
                payload = do_load()
                self.after(0, lambda p=payload: self._open_group_permissions_window(
                    account_id, group_id, *p
                ))
            except Exception as e:
                self.after(0, lambda err=e: messagebox.showerror(
                    "Error", f"Could not load group permissions:\n\n{err}", parent=self
                ))

        threading.Thread(target=worker, daemon=True).start()

    def _open_group_permissions_window(
        self,
        account_id: str,
        group_id: str,
        group: dict,
        access: str,
        existing_perm_ids: set,
        existing_res_id: Optional[str],
        perm_groups: list,
        res_groups: list,
    ):
        win = ctk.CTkToplevel(self)
        win.title(f"Permission Policies - {group.get('name', '(group)')}")
        win.geometry("700x620")
        win.transient(self)
        win.grab_set()
        win.configure(fg_color="#000000")

        ctk.CTkLabel(
            win,
            text=f"Permission Policies for {group.get('name', '(group)')}",
            text_color="#ffffff",
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor="w", padx=16, pady=(16, 6))

        access_var = tk.StringVar(value=("deny" if access == "deny" else "allow"))

        access_row = ctk.CTkFrame(win, fg_color="#000000")
        access_row.pack(fill="x", padx=16, pady=(0, 10))

        ctk.CTkLabel(access_row, text="Access:", text_color="#ffffff").pack(side="left")

        ctk.CTkRadioButton(
            access_row, text="Allow", value="allow", variable=access_var,
            fg_color="#0078d4", hover_color="#106ebe"
        ).pack(side="left", padx=(10, 0))

        ctk.CTkRadioButton(
            access_row, text="Deny", value="deny", variable=access_var,
            fg_color="#0078d4", hover_color="#106ebe"
        ).pack(side="left", padx=(10, 0))

        # Resource Groups dropdown
        ctk.CTkLabel(win, text="Resource Group:", text_color="#ffffff").pack(anchor="w", padx=16)

        rg_id_to_label: Dict[str, str] = {}
        rg_labels: List[str] = []

        for rg in (res_groups or []):
            rid = rg.get("id")
            meta = rg.get("meta") or {}
            label = meta.get("name") or rid or "(unknown)"
            if rid:
                rg_id_to_label[rid] = label
                rg_labels.append(label)

        if not rg_labels:
            rg_labels = ["(no resource groups)"]

        rg_choice = tk.StringVar(value=rg_id_to_label.get(existing_res_id or "", rg_labels[0]))

        ctk.CTkComboBox(
            win,
            values=rg_labels,
            variable=rg_choice,
            state="readonly",
            width=520,
            fg_color="#1a1a1a",
            button_color="#444444",
            button_hover_color="#555555",
            border_color="#333333",
            text_color="#ffffff",
        ).pack(anchor="w", padx=16, pady=(6, 14))

        # Permission Groups checkboxes
        ctk.CTkLabel(win, text="Permission Groups:", text_color="#ffffff").pack(anchor="w", padx=16)

        scroll = ctk.CTkScrollableFrame(win, fg_color="#000000")
        scroll.pack(fill="both", expand=True, padx=16, pady=(6, 12))

        perm_vars: Dict[str, tk.BooleanVar] = {}

        for pg in sorted(perm_groups, key=lambda x: (x.get("name") or "").lower()):
            pid = pg.get("id")
            pname = pg.get("name") or pid or "(unnamed)"
            if not pid:
                continue

            var = tk.BooleanVar(value=(pid in existing_perm_ids))
            perm_vars[pid] = var

            row = ctk.CTkFrame(scroll, fg_color="#111111", corner_radius=8)
            row.pack(fill="x", padx=4, pady=4)

            ctk.CTkCheckBox(
                row,
                text=pname,
                variable=var,
                onvalue=True,
                offvalue=False,
                text_color="#ffffff",
                fg_color="#0078d4",
                hover_color="#106ebe",
            ).pack(anchor="w", padx=10, pady=10)

        btns = ctk.CTkFrame(win, fg_color="#000000")
        btns.pack(fill="x", padx=16, pady=(0, 16))

        def on_cancel():
            win.destroy()

        def on_save():
            chosen_label = rg_choice.get()
            chosen_rg_id = None
            for rid, lab in rg_id_to_label.items():
                if lab == chosen_label:
                    chosen_rg_id = rid
                    break

            selected_perm_ids = [pid for pid, var in perm_vars.items() if var.get()]

            new_policies = [{
                "access": access_var.get(),
                "permission_groups": [{"id": pid} for pid in selected_perm_ids],
                "resource_groups": [{"id": chosen_rg_id}] if chosen_rg_id else [],
            }]

            def do_update():
                cf = self._client_for("groups_edit")
                # NOTE: this requires CloudflareClient.update_user_group(..., policies=...)
                cf.update_user_group(account_id, group_id, name=group.get("name"), policies=new_policies)
                self.after(0, self.refresh_now)
                return "Updated group permission policies."

            def bg():
                try:
                    msg = do_update()
                    self.after(0, lambda: (self._append(msg), win.destroy()))
                except Exception as e:
                    self.after(0, lambda err=e: messagebox.showerror(
                        "Error",
                        f"Failed to update permission policies:\n\n{err}",
                        parent=self,
                    ))

            threading.Thread(target=bg, daemon=True).start()

        ctk.CTkButton(
            btns, text="Save", command=on_save,
            fg_color="#0078d4", hover_color="#106ebe", width=120
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btns, text="Cancel", command=on_cancel,
            fg_color="#333333", hover_color="#444444", width=120
        ).pack(side="left")

    # ----- group member add/remove/rename -----
    def _add_member_to_group(self, group_id: str):
        account_id = self.selected_account_id.get().strip()
        if not account_id:
            messagebox.showerror("Error", "Select an account first.", parent=self)
            return

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
            self._ui(self.refresh_now)
            return f"Added {email} to group {group_id}"

        self._run_bg("Add Member To Group", do)

    def _remove_member_from_group(self, group_id: str) -> None:
        account_id = self.selected_account_id.get().strip()
        if not account_id:
            messagebox.showerror("Error", "Select an account first.", parent=self)
            return

        # Load current group members (prefer cache if fresh)
        try:
            members = self._get_cached_group_members(group_id)
            if members is None:
                cf = self._client_for("groups_read")
                resp = cf.list_user_group_members(account_id, group_id)
                members = resp.get("result") or []
                self._group_members_cache[group_id] = (time.time(), members)
        except Exception as e:
            messagebox.showerror("Error", f"Could not load group members:\n\n{e}", parent=self)
            return

        if not members:
            messagebox.showinfo("No Members", "This group has no members.", parent=self)
            return

        selected = self._pick_group_member_dialog(members, title="Remove Member from Group")
        if not selected:
            return

        member_id = (selected.get("id") or "").strip()
        email = self._member_email(selected)

        if not member_id:
            messagebox.showerror("Error", "Selected member is missing an id.", parent=self)
            return

        if not messagebox.askyesno("Remove Member", f"Remove {email} from this group?"):
            return

        def do():
            cf = self._client_for("groups_edit")
            cf.remove_member_from_user_group(account_id, group_id, member_id)

            # clear cache for this group so UI updates
            self._group_members_cache.pop(group_id, None)
            self._ui(self.refresh_now)
            return f"Removed {email} from group {group_id}"

        self._run_bg("Remove Member From Group", do)

    def _get_cached_group_members(self, group_id: str) -> Optional[List[dict]]:
        cached = self._group_members_cache.get(group_id)
        if not cached:
            return None
        ts, members = cached
        if (time.time() - ts) < self._group_members_ttl:
            return members
        return None

    @staticmethod
    def _member_email(member: dict) -> str:
        # group member objects may be either {"email": "..."} or {"user": {"email": "..."}} or something else
        if isinstance(member, dict):
            if member.get("email"):
                return str(member["email"])
            user = member.get("user")
            if isinstance(user, dict) and user.get("email"):
                return str(user["email"])
        return "(unknown)"

    # ---------------- dialogs ----------------
    def _pick_member_dialog(self, members: List[dict], title: str = "Select Member") -> Optional[dict]:
        if not members:
            messagebox.showinfo("No Members", "No account members are available to choose from.", parent=self)
            return None

        dialog = ctk.CTkToplevel(self)
        dialog.title(title)
        dialog.geometry("520x420")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(fg_color="#000000")

        ctk.CTkLabel(dialog, text=title, text_color="#ffffff", font=("Segoe UI", 18, "bold")).pack(
            anchor="w", padx=16, pady=(16, 8)
        )

        selected = {"value": None}

        scroll = ctk.CTkScrollableFrame(dialog, fg_color="#000000")
        scroll.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        def _select(member):
            selected["value"] = member
            dialog.destroy()

        for m in members:
            user = m.get("user") or {}
            email = user.get("email", "(no email)")
            member_id = m.get("id", "")
            status = m.get("status", "")

            row = ctk.CTkFrame(scroll, fg_color="#111111", corner_radius=8)
            row.pack(fill="x", padx=4, pady=4)

            text = f"{email}\nstatus={status} | id={member_id}"
            ctk.CTkButton(
                row,
                text=text,
                anchor="w",
                height=54,
                fg_color="#1a1a1a",
                hover_color="#2a2a2a",
                text_color="#ffffff",
                command=lambda member=m: _select(member),
            ).pack(fill="x", padx=8, pady=8)

        dialog.wait_window()
        return selected["value"]

    # Add Member dialog (email + roles) from main_app.py
    def _add_members_dialog(self, all_roles: List[dict], title: str = "Select Roles") -> Optional[dict]:
        dialog = ctk.CTkToplevel(self)
        dialog.title(title)
        dialog.geometry("560x520")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(fg_color="#000000")

        result = {"value": None}

        ctk.CTkLabel(dialog, text="Member Email", text_color="#ffffff",
                     font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=16, pady=(16, 8))

        email_entry = ctk.CTkEntry(dialog, placeholder_text="user@example.com", width=520)
        email_entry.pack(anchor="w", padx=16, pady=(0, 12))

        ctk.CTkLabel(dialog, text=title, text_color="#ffffff",
                     font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=16, pady=(6, 8))

        scroll = ctk.CTkScrollableFrame(dialog, fg_color="#000000")
        scroll.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        role_vars: Dict[str, tk.BooleanVar] = {}

        for role in sorted(all_roles, key=lambda r: (r.get("name") or "").lower()):
            role_name = role.get("name", "(unnamed role)")
            var = tk.BooleanVar(value=False)
            role_vars[role_name] = var

            row = ctk.CTkFrame(scroll, fg_color="#111111", corner_radius=8)
            row.pack(fill="x", padx=4, pady=4)

            ctk.CTkCheckBox(
                row,
                text=role_name,
                variable=var,
                onvalue=True,
                offvalue=False,
                text_color="#ffffff",
                fg_color="#0078d4",
                hover_color="#106ebe",
            ).pack(anchor="w", padx=10, pady=10)

        btns = ctk.CTkFrame(dialog, fg_color="#000000")
        btns.pack(fill="x", padx=16, pady=(0, 16))

        def on_save():
            email = email_entry.get().strip()
            if not email:
                messagebox.showerror("Missing email", "Email is required.", parent=dialog)
                return

            chosen_roles = [name for name, var in role_vars.items() if var.get()]
            if not chosen_roles:
                messagebox.showerror("No roles", "Select at least one role.", parent=dialog)
                return

            result["value"] = {"email": email, "roles": chosen_roles}
            dialog.destroy()

        def on_cancel():
            result["value"] = None
            dialog.destroy()

        ctk.CTkButton(btns, text="Save", command=on_save,
                      fg_color="#0078d4", hover_color="#106ebe", width=120).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btns, text="Cancel", command=on_cancel,
                      fg_color="#333333", hover_color="#444444", width=120).pack(side="left")

        dialog.wait_window()
        return result["value"]

    def _format_group_permissions(self, group_detail: dict) -> str:
        policies = group_detail.get("policies", []) or []
        if not policies:
            return "No group permissions assigned"

        found = []

        for policy in policies:
            if not isinstance(policy, dict):
                continue

            # Common possible shapes
            for field in ("permission_groups", "permissions", "roles"):
                items = policy.get(field, []) or []
                for item in items:
                    if isinstance(item, dict):
                        name = (
                                item.get("name")
                                or item.get("label")
                                or item.get("permission")
                                or item.get("id")
                                or ""
                        ).strip()
                    else:
                        name = str(item).strip()

                    if name:
                        found.append(name)

        # Deduplicate, preserve order
        seen = set()
        unique = []
        for name in found:
            key = name.lower()
            if key not in seen:
                seen.add(key)
                unique.append(name)

        if not unique:
            return "No permissions assigned"

        # Keep cards readable
        if len(unique) <= 5:
            return ", ".join(unique)

        return ", ".join(unique[:5]) + f" +{len(unique) - 5} more"

    def _format_full_group_permissions(self, group_detail: dict) -> str:
        policies = group_detail.get("policies", []) or []
        if not policies:
            return "No group permissions assigned"

        found = []

        for policy in policies:
            if not isinstance(policy, dict):
                continue

            for field in ("permission_groups", "permissions", "roles"):
                items = policy.get(field, []) or []
                for item in items:
                    if isinstance(item, dict):
                        name = (
                                item.get("name")
                                or item.get("label")
                                or item.get("permission")
                                or item.get("id")
                                or ""
                        ).strip()
                    else:
                        name = str(item).strip()

                    if name:
                        found.append(name)

        # Deduplicate
        seen = set()
        unique = []
        for name in found:
            key = name.lower()
            if key not in seen:
                seen.add(key)
                unique.append(name)

        if not unique:
            return "No permissions assigned"

        # 🔥 return ALL permissions
        return ", ".join(unique)


    def _get_full_member_permissions(self, m: dict) -> str:
        # This code just basically updates the members permissions under their member cards to have their full personal and group permissions.
        account_id = self.selected_account_id.get().strip()
        cf = self._client_for("groups_read")

        permissions_text = ""

        # If they have a group add it onto the permissions they have
        if m.get("user_groups"):
            for i in range(len(m.get("user_groups"))):
                user_group_id = (m["user_groups"][i].get("id"))
                resp = cf.get_user_group(account_id, user_group_id)
                group_detail = resp.get("result") or {}
                permissions_text = ", " + self._format_full_group_permissions(group_detail)
                if permissions_text == "No permissions assigned":
                    permissions_text = ""

        # Personal permissions add it together
        roles = m.get("roles") or []
        role_names = [r.get("name", "") for r in roles if isinstance(r, dict)]
        roles_text = ", ".join([r for r in role_names if r]) or "(no roles)"
        roles_text += permissions_text

        return roles_text

    def _pick_group_member_dialog(self, members: List[dict], title: str = "Select Group Member") -> Optional[dict]:
        """
        Similar to _pick_member_dialog, but expects list_user_group_members payload objects.
        Returns selected group-member dict or None.
        """
        dialog = ctk.CTkToplevel(self)
        dialog.title(title)
        dialog.geometry("520x420")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(fg_color="#000000")

        ctk.CTkLabel(dialog, text=title, text_color="#ffffff", font=("Segoe UI", 18, "bold")).pack(
            anchor="w", padx=16, pady=(16, 8)
        )

        selected: Dict[str, Optional[dict]] = {"value": None}

        scroll = ctk.CTkScrollableFrame(dialog, fg_color="#000000")
        scroll.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        def _select(m: dict) -> None:
            selected["value"] = m
            dialog.destroy()

        for m in members:
            email = self._member_email(m)
            mid = (m.get("id") or "")
            text = f"{email}\nid={mid}"

            row = ctk.CTkFrame(scroll, fg_color="#111111", corner_radius=8)
            row.pack(fill="x", padx=4, pady=4)

            ctk.CTkButton(
                row,
                text=text,
                anchor="w",
                height=54,
                fg_color="#1a1a1a",
                hover_color="#2a2a2a",
                text_color="#ffffff",
                command=lambda mm=m: _select(mm),
            ).pack(fill="x", padx=8, pady=8)

        dialog.wait_window()
        return selected["value"]

    def _pick_roles_dialog(self, all_roles, selected_role_ids=None, title="Select Roles") -> Optional[List[str]]:
        selected_role_ids = set(selected_role_ids or [])

        dialog = ctk.CTkToplevel(self)
        dialog.title(title)
        dialog.geometry("560x500")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(fg_color="#000000")

        result = {"value": None}

        ctk.CTkLabel(dialog, text=title, text_color="#ffffff",
                     font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=16, pady=(16, 8))

        scroll = ctk.CTkScrollableFrame(dialog, fg_color="#000000")
        scroll.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        role_vars: Dict[str, tk.BooleanVar] = {}

        for role in sorted(all_roles, key=lambda r: (r.get("name", "").lower())):
            role_id = role.get("id", "")
            role_name = role.get("name", "(unnamed role)")
            var = tk.BooleanVar(value=(role_id in selected_role_ids))
            role_vars[role_id] = var

            row = ctk.CTkFrame(scroll, fg_color="#111111", corner_radius=8)
            row.pack(fill="x", padx=4, pady=4)

            ctk.CTkCheckBox(
                row,
                text=role_name,
                variable=var,
                onvalue=True,
                offvalue=False,
                text_color="#ffffff",
                fg_color="#0078d4",
                hover_color="#106ebe",
            ).pack(anchor="w", padx=10, pady=10)

        btns = ctk.CTkFrame(dialog, fg_color="#000000")
        btns.pack(fill="x", padx=16, pady=(0, 16))

        def on_save():
            chosen = [role_id for role_id, var in role_vars.items() if var.get()]
            if not chosen:
                messagebox.showerror("Invalid selection", "Select at least one role.", parent=dialog)
                return
            result["value"] = chosen
            dialog.destroy()

        def on_cancel():
            result["value"] = None
            dialog.destroy()

        ctk.CTkButton(btns, text="Save", command=on_save,
                      fg_color="#0078d4", hover_color="#106ebe", width=120).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btns, text="Cancel", command=on_cancel,
                      fg_color="#333333", hover_color="#444444", width=120).pack(side="left")

        dialog.wait_window()
        return result["value"]

    # ---------------- CRUD helpers ----------------
    def _rename_group(self, group_id: str, name_label):
        new_name = simpledialog.askstring("Rename Group", "Enter new group name:", parent=self)
        if not new_name:
            return

        def do():
            account_id = self.selected_account_id.get().strip()
            cf = self._client_for("groups_edit")
            result = cf.update_user_group(account_id, group_id, new_name)["result"]
            final_name = result.get("name", new_name)
            self._ui(lambda n=final_name: name_label.configure(text=n))
            return f"Renamed group to: {final_name}"

        self._run_bg("Rename Group", do)

    def _delete_group(self, group_id: str, card):
        if not messagebox.askyesno("Delete Group", "Delete this group?"):
            return

        def do():
            account_id = self.selected_account_id.get().strip()
            cf = self._client_for("groups_edit")
            cf.delete_user_group(account_id, group_id)
            self._ui(card.destroy)
            return f"Deleted group: {group_id}"

        self._run_bg("Delete Group", do)

    def _is_network_error(self, err: Exception) -> bool:
        return isinstance(err, (ConnectionError, Timeout))

    def _next_backoff_ms(self) -> int:
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

            self._ui(update_ui)
            return f"Loaded {len(self.accounts)} accounts."

        self._run_bg("List Accounts", do)

    def _scan_member_risk(self, members: list) -> str:
        # This is our AI prompting and we just grab the list that we do in function return all users information and pass it into this prompt.
        prompt = (
            f"In the list {members}, there is a list inside of a list with members with their own emails, roles, and groups. provide me with an overall risk level "
            f"of low, medium, high, and critical of each member if they were properly trained off the roles they have"
            f"At the end, also provide an overall risk level of all the roles combined together for each member.\n\n"
            f"Format (Do not include any other words other than the actual permission themselves do this for each member):\n"
            f"User: "
            f"Group(s): "
            f"Overall Risk Level:"
            f"Reason:"
            f"Low Risk Roles: (Role, Role, Role...)"
            f"Medium Risk Roles: (Role, Role, Role...)"
            f"High Risk Roles: (Role, Role, Role...)"
            f"Critical Risk Roles: (Role, Role, Role...)"
        )

        response = g4f.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2
        )

        return response

    def _return_all_users_information(self):
        # here is the magic, just go through some exceptions
        account_id = self.selected_account_id.get().strip()
        if not account_id:
            messagebox.showerror("Error", "Select an account first.", parent=self)
            return

        try:
            members = self._client_for("members_read").list_members(account_id).get("result") or []
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load members:\n\n{e}", parent=self)
            return

        # This is the window for the vulnerability scan
        win = ctk.CTkToplevel(self)
        win.title("Vulnerability Scan Results")
        win.geometry("900x700")
        win.configure(fg_color="#000000")

        win.lift()
        win.attributes("-topmost", True)
        win.after(200, lambda: win.attributes("-topmost", False))
        win.focus_force()

        ctk.CTkLabel(
            win,
            text="Vulnerability Scan",
            font=("Segoe UI", 30, "bold"),
            text_color="#ffffff",
            justify="center"
        ).pack(anchor="w", padx=16, pady=(16, 8))

        container = ctk.CTkScrollableFrame(win, fg_color="#000000")
        container.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        # This takes the code from my full members permission and then joins it together into a list so that we get the user email, user roles, and user groups.
        def worker():
            full_prompting_info = []

            for m in members:
                try:
                    user = m.get("user") or {}
                    email = user.get("email", "(no email)")
                    roles_text = self._get_full_member_permissions(m)

                    group_names = []
                    if m.get("user_groups"):
                        for g in m["user_groups"]:
                            name = g.get("name")
                            if name:
                                group_names.append(name)

                    group_name = ", ".join(group_names) or "No Group"

                    full_prompting_info.append({
                        "email": email,
                        "roles": roles_text,
                        "groups": group_name
                    })

                except Exception as e:
                    self._ui(lambda err=e: print(f"[ERROR] {err}"))

            # Scan the members with the prompt of the members list.
            result = self._scan_member_risk(full_prompting_info)
            
            self._ui(self._render_scan_results, container, result)

        threading.Thread(target=worker, daemon=True).start()

    # merged Add Member uses email+roles picker (main_app.py)
    def add_member(self):
        account_id = self.selected_account_id.get().strip()
        if not account_id:
            messagebox.showerror("Error", "Select an account first.", parent=self)
            return

        try:
            cf = self._get_client()
            data = cf.list_roles(account_id)
            self.roles = data.get("result") or []
        except Exception as e:
            messagebox.showerror("Error", f"Could not load roles:\n\n{e}", parent=self)
            return

        add_member_output = self._add_members_dialog(self.roles, title="Select Roles")
        if not add_member_output:
            return

        email = (add_member_output.get("email") or "").strip()
        role_input = add_member_output.get("roles") or []
        if not email or not role_input:
            return

        def do():
            account_id2 = self.selected_account_id.get().strip()
            if not account_id2:
                raise ValueError("Select an account first.")

            cf2 = self._client_for("members_edit")

            if not self.role_name_to_id:
                data2 = cf2.list_roles(account_id2)
                self.roles = data2.get("result") or []
                self.role_name_to_id = {r["name"]: r["id"] for r in self.roles if r.get("name") and r.get("id")}
                self.role_id_to_name = {r["id"]: r["name"] for r in self.roles if r.get("name") and r.get("id")}

            role_ids: List[str] = []
            unknown: List[str] = []

            for role_name in role_input:
                if role_name in self.role_name_to_id:
                    role_ids.append(self.role_name_to_id[role_name])
                elif isinstance(role_name, str) and len(role_name) >= 20:
                    role_ids.append(role_name)
                else:
                    unknown.append(str(role_name))

            if unknown:
                raise ValueError(f"Unknown role names: {unknown}")

            result = cf2.add_member(account_id2, email, role_ids)
            self._ui(self.refresh_now)
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
            self._ui(self.refresh_now)
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
            self.role_name_to_id = {r["name"]: r["id"] for r in self.roles if r.get("name") and r.get("id")}
            self.role_id_to_name = {r["id"]: r["name"] for r in self.roles if r.get("name") and r.get("id")}
            out = ["Roles:"]
            for r in self.roles:
                out.append(f"- {r['name']} | id={r['id']}")
            return "\n".join(out)

        self._run_bg("List Roles", do)

    def refresh_now(self):
        def do():
            account_id = self.selected_account_id.get().strip()
            if not account_id:
                raise ValueError("Select an account first.")

            members = self._client_for("members_read").list_members(account_id).get("result") or []
            groups = self._client_for("groups_read").list_user_groups(account_id).get("result") or []

            self._ui(self._render_members_cards, members)
            self._ui(self._render_groups_cards, groups)
            self._ui(self._set_status, "Auto-refreshed.")
            self._ui(self._append, f"Refreshed: {len(members)} members, {len(groups)} groups.")
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
        account_id = self.selected_account_id.get().strip()
        network_failed = False

        try:
            try:
                members = self._client_for("members_read").list_members(account_id).get("result") or []
                self._ui(self._render_members_cards, members)
            except Exception as e:
                if self._is_network_error(e):
                    network_failed = True
                self._ui(self._append, f"[AUTO-REFRESH ERROR][members] {repr(e)}")

            try:
                groups = self._client_for("groups_read").list_user_groups(account_id).get("result") or []
                self._ui(self._render_groups_cards, groups)
            except Exception as e:
                if self._is_network_error(e):
                    network_failed = True
                self._ui(self._append, f"[AUTO-REFRESH ERROR][groups] {repr(e)}")

        finally:
            def finalize():
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

            self._ui(finalize)

    # ---------------- Token Manager ----------------
    def open_token_manager(self):
        def on_saved(_tokens):
            self.saved_tokens = self.store.load()
            for k in self.tokens:
                self.tokens[k].set(self.saved_tokens.get(k, ""))
            self._load_selected_token_into_entry()
            self._append("Tokens reloaded from disk.")

        TokenManagerWindow(self, on_saved=on_saved)

    def _on_close(self):
        self.stop_auto_refresh()
        self.destroy()