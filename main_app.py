# Cloudflare IAM Explorer
# main app

import threading
import tkinter as tk
from tkinter import messagebox, simpledialog
import customtkinter as ctk
import time

from decorator import EMPTY
from requests.exceptions import ConnectionError, Timeout
from typing import Optional, Callable, Any, Dict, List, Tuple

from cloudflare_client import CloudflareClient
from permission_service import GroupPermissionService
from scan_service import RiskScanService
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

        # anti-spam:
        self._refresh_cooldown = False

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
        self._risk_scan_cache: Dict[str, dict] = {}
        self._group_permission_names_cache: Dict[str, List[str]] = {}
        self._member_permission_summary_cache: Dict[str, str] = {}
        self._all_members: List[dict] = []
        self._all_groups: List[dict] = []
        self._members_loaded_account_id: Optional[str] = None
        self._groups_loaded_account_id: Optional[str] = None
        self._member_card_pool: List[Dict[str, Any]] = []
        self._member_empty_label = None
        self._member_filter_job = None
        self._scan_window = None
        self._auto_refresh_paused_for_scan = False
        self.member_search_var = tk.StringVar(value="")
        self.member_results_var = tk.StringVar(value="No members loaded")
        self.permission_service = GroupPermissionService()
        self.scan_service = RiskScanService()

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

        self.refresh_button = ctk.CTkButton(
            btns,
            text="Refresh Now",
            command=self.refresh_now,
            fg_color="#0078d4",
            hover_color="#106ebe",
        )
        self.refresh_button.pack(side="left", padx=(0, 8))

        ctk.CTkButton(btns, text="Manage Tokens", command=self.open_token_manager,
                      fg_color="#333333", hover_color="#444444").pack(side="left", padx=(8, 0))

        self.scan_button = ctk.CTkButton(
            btns,
            text="Launch Scan",
            command=self.scan_all_members,
            fg_color="#333333",
            hover_color="#444444",
        )
        self.scan_button.pack(side="left", padx=(8, 0))

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

        members_toolbar = ctk.CTkFrame(members_tab, fg_color="#000000")
        members_toolbar.pack(fill="x", padx=10, pady=(10, 0))

        ctk.CTkLabel(members_toolbar, text="Search members:", text_color="#ffffff").pack(side="left", padx=(0, 8))

        self.member_search_entry = ctk.CTkEntry(
            members_toolbar,
            textvariable=self.member_search_var,
            width=320,
            placeholder_text="Email, member ID, status, role, or group",
            fg_color="#1a1a1a",
            border_color="#333333",
            text_color="#ffffff",
        )
        self.member_search_entry.pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            members_toolbar,
            text="Clear",
            command=self._clear_member_search,
            width=80,
            fg_color="#333333",
            hover_color="#444444",
        ).pack(side="left")

        ctk.CTkLabel(
            members_toolbar,
            textvariable=self.member_results_var,
            text_color="#4ec9b0",
        ).pack(side="right")

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
        self.member_search_var.trace_add("write", self._on_member_search_changed)

    # ---------------- UI helpers ----------------
    def _set_status(self, text: str):
        self.status_var.set(text)

    def _reenable_refresh_button(self):
        self._refresh_cooldown = False
        if hasattr(self, "refresh_button"):
            self.refresh_button.configure(state="normal", text="Refresh Now")

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

    def open_scan_window(self):
        """Open the scan results window and pause scan-conflicting controls."""
        win = ctk.CTkToplevel(self)
        win.title("Vulnerability Scan Results")
        win.geometry("800x600")
        win.configure(fg_color="#000000")
        win.transient(self)
        self._scan_window = win

        if hasattr(self, "scan_button"):
            self.scan_button.configure(state="disabled")
        if hasattr(self, "refresh_button"):
            self.refresh_button.configure(state="disabled")
        self.stop_auto_refresh()
        self._auto_refresh_paused_for_scan = True

        ctk.CTkLabel(
            win,
            text="Vulnerability Scan",
            font=("Segoe UI", 18, "bold"),
            text_color="#ffffff"
        ).pack(anchor="w", padx=16, pady=(16, 8))

        scan_status_var = tk.StringVar(value="Preparing scan...")
        ctk.CTkLabel(
            win,
            textvariable=scan_status_var,
            text_color="#4ec9b0",
            font=("Segoe UI", 12, "bold")
        ).pack(anchor="w", padx=16, pady=(0, 8))

        output = ctk.CTkTextbox(
            win,
            fg_color="#1a1a1a",
            text_color="#ffffff",
            font=("Consolas", 12)
        )
        output.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        output._textbox.configure(wrap="none", tabs=("300",))
        self._configure_scan_output_tags(output)
        output.insert("end", "Scanning members by group...\n")

        def on_close():
            if hasattr(self, "scan_button") and self.scan_button.winfo_exists():
                self.scan_button.configure(state="normal")
            if hasattr(self, "refresh_button") and self.refresh_button.winfo_exists():
                if self._refresh_cooldown:
                    self.refresh_button.configure(state="disabled")
                else:
                    self.refresh_button.configure(state="normal", text="Refresh Now")
            self._scan_window = None
            if self._auto_refresh_paused_for_scan:
                self._auto_refresh_paused_for_scan = False
                self.start_auto_refresh(self._refresh_interval_ms)
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", on_close)

        return win, scan_status_var, output

    @staticmethod
    def _scan_textbox(output):
        return getattr(output, "_textbox", output)

    def _configure_scan_output_tags(self, output) -> None:
        textbox = self._scan_textbox(output)
        textbox.tag_configure("scan_header", foreground="#4ec9b0", font=("Segoe UI", 14, "bold"))
        textbox.tag_configure("scan_member", foreground="#ffffff", font=("Consolas", 12, "bold"))
        textbox.tag_configure("scan_muted", foreground="#a0a0a0")
        textbox.tag_configure("risk_low", foreground="#4ec9b0")
        textbox.tag_configure("risk_medium", foreground="#ffd166")
        textbox.tag_configure("risk_high", foreground="#ff9f1c")
        textbox.tag_configure("risk_critical", foreground="#ff4d4f")

    def _append_scan_text(self, output, text: str, tag: Optional[str] = None) -> None:
        textbox = self._scan_textbox(output)
        if tag:
            textbox.insert("end", text, tag)
        else:
            textbox.insert("end", text)
        textbox.see("end")

    def _set_scan_status(self, scan_status_var: Optional[tk.StringVar], text: str) -> None:
        if scan_status_var is not None:
            scan_status_var.set(text)
        self._set_status(text)

    @staticmethod
    def _member_group_names(member: dict) -> List[str]:
        names: List[str] = []
        seen = set()

        for group in member.get("user_groups") or []:
            if not isinstance(group, dict):
                continue
            name = (group.get("name") or "").strip()
            if not name:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            names.append(name)

        return names

    def _render_member_risk_summary(self, output, parsed_result: dict) -> None:
        overall = parsed_result.get("overall") or "Unknown"
        self._append_scan_text(output, f"[{overall.upper()}] ", self.scan_service.risk_tag_for_level(overall))

        critical_permissions = parsed_result.get("critical") or []
        high_permissions = parsed_result.get("high") or []

        rendered_any = False

        if critical_permissions:
            self._append_scan_text(output, "Critical: ", "risk_critical")
            for index, permission in enumerate(critical_permissions):
                if index:
                    self._append_scan_text(output, ", ", "scan_muted")
                self._append_scan_text(output, permission, "risk_critical")
            rendered_any = True

        if high_permissions:
            if rendered_any:
                self._append_scan_text(output, " | ", "scan_muted")
            self._append_scan_text(output, "High: ", "risk_high")
            for index, permission in enumerate(high_permissions):
                if index:
                    self._append_scan_text(output, ", ", "scan_muted")
                self._append_scan_text(output, permission, "risk_high")
            rendered_any = True

        if not rendered_any:
            raw = (parsed_result.get("raw") or "").splitlines()
            fallback_line = raw[0].strip() if raw else ""
            if fallback_line and overall == "Unknown":
                self._append_scan_text(output, fallback_line, "scan_muted")
            else:
                self._append_scan_text(output, "No high-risk permissions found", "scan_muted")

    def _render_grouped_scan_results(
        self,
        output,
        group_names: List[str],
        grouped_results: Dict[str, List[dict]],
        errors: List[str],
    ) -> None:
        """Render grouped scan results into the scan window textbox."""
        if hasattr(output, "winfo_exists") and not output.winfo_exists():
            return

        textbox = self._scan_textbox(output)
        if hasattr(textbox, "winfo_exists") and not textbox.winfo_exists():
            return
        textbox.delete("1.0", "end")

        if not group_names and not errors:
            self._append_scan_text(output, "No groups or members found.\n", "scan_muted")
            return

        for group_name in group_names:
            self._append_scan_text(output, f"{group_name}\n", "scan_header")
            members = sorted(grouped_results.get(group_name, []), key=lambda item: item["email"].lower())

            if not members:
                self._append_scan_text(output, "  (no members)\n\n", "scan_muted")
                continue

            for member in members:
                self._append_scan_text(output, "  ", None)
                self._append_scan_text(output, member["email"], "scan_member")
                self._append_scan_text(output, "\t", None)
                self._render_member_risk_summary(output, member["risk"])
                self._append_scan_text(output, "\n")

            self._append_scan_text(output, "\n", None)

        if errors:
            self._append_scan_text(output, "Errors\n", "scan_header")
            for err in errors:
                self._append_scan_text(output, f"  {err}\n", "risk_critical")

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
        """Update the selected account id when the account dropdown changes."""
        selection = self.account_combo.get().strip()
        if "(" in selection and selection.endswith(")"):
            account_id = selection.split("(")[-1][:-1].strip()
            if len(account_id) == 32:
                self.selected_account_id.set(account_id)
                self._member_permission_summary_cache.clear()
                self._all_members = []
                self._all_groups = []
                self._members_loaded_account_id = None
                self._groups_loaded_account_id = None
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

    def _on_member_search_changed(self, *_args) -> None:
        """Debounce member search updates so the UI does less work while typing."""
        if self._member_filter_job is not None:
            try:
                self.after_cancel(self._member_filter_job)
            except Exception:
                pass
        self._member_filter_job = self.after(120, self._run_member_filter)

    def _run_member_filter(self) -> None:
        """Run the pending member filter update now."""
        self._member_filter_job = None
        self._apply_member_filter()

    def _clear_member_search(self) -> None:
        """Clear the member search box and restore the full member list."""
        self.member_search_var.set("")

    def _set_members(self, members: List[dict], account_id: Optional[str] = None) -> None:
        """Store the latest member payload and render the filtered view."""
        self._all_members = list(members or [])
        self._members_loaded_account_id = account_id or self.selected_account_id.get().strip()
        self._apply_member_filter()

    def _set_groups(self, groups: List[dict], account_id: Optional[str] = None) -> None:
        """Store the latest group payload and render the group cards."""
        self._all_groups = list(groups or [])
        self._groups_loaded_account_id = account_id or self.selected_account_id.get().strip()
        self._render_groups_cards(self._all_groups)

    def _apply_member_filter(self) -> None:
        """Render only the members that match the current search text."""
        filtered_members = self._filter_members(self._all_members, self.member_search_var.get())
        total_members = len(self._all_members)
        shown_members = len(filtered_members)

        if total_members == 0:
            self.member_results_var.set("No members loaded")
        elif (self.member_search_var.get() or "").strip():
            self.member_results_var.set(f"Showing {shown_members} of {total_members} members")
        else:
            self.member_results_var.set(f"{total_members} members")

        self._render_members_cards(filtered_members)

    def _filter_members(self, members: List[dict], query: str) -> List[dict]:
        """Return only the members whose key fields contain the search query."""
        normalized_query = (query or "").strip().lower()
        if not normalized_query:
            return list(members or [])

        filtered: List[dict] = []
        for member in members or []:
            if normalized_query in self._member_search_blob(member):
                filtered.append(member)
        return filtered

    def _member_search_blob(self, member: dict) -> str:
        """Build the searchable text blob for one member row."""
        user = member.get("user") or {}
        email = user.get("email", "")
        member_id = member.get("id", "")
        status = member.get("status", "")
        role_names = [role.get("name", "") for role in (member.get("roles") or []) if isinstance(role, dict)]
        group_names = [group.get("name", "") for group in (member.get("user_groups") or []) if isinstance(group, dict)]
        return " ".join([email, member_id, status, *role_names, *group_names]).lower()

    def _member_permissions_summary(self, account_id: str, member: dict) -> str:
        """Return the cached permission summary for the member's first group."""
        user_groups = member.get("user_groups") or []
        if not user_groups:
            return ""

        first_group = user_groups[0] if isinstance(user_groups[0], dict) else {}
        group_id = (first_group.get("id") or "").strip()
        if not group_id:
            return ""

        cache_key = f"{account_id}:{group_id}"
        cached_summary = self._member_permission_summary_cache.get(cache_key)
        if cached_summary is not None:
            return cached_summary

        cached_permissions = self._group_permission_names_cache.get(cache_key)
        if cached_permissions is not None:
            permissions_text = ", ".join(cached_permissions[:5])
            if len(cached_permissions) > 5:
                permissions_text += f" +{len(cached_permissions) - 5} more"
            self._member_permission_summary_cache[cache_key] = permissions_text
            return permissions_text

        try:
            cf = self._client_for("groups_read")
            resp = cf.get_user_group(account_id, group_id)
            group_detail = resp.get("result") or {}
            permission_names = self.permission_service.extract_group_permission_names(group_detail)
            self._group_permission_names_cache[cache_key] = permission_names
            permissions_text = self.permission_service.format_group_permissions(group_detail)
            if permissions_text == "No permissions assigned":
                permissions_text = ""
        except Exception:
            permissions_text = ""

        self._member_permission_summary_cache[cache_key] = permissions_text
        return permissions_text

    def _cached_group_permissions_for_account(self, account_id: str) -> Dict[str, List[str]]:
        """Return the cached group-permission names for the selected account."""
        prefix = f"{account_id}:"
        return {
            cache_key[len(prefix):]: list(permission_names)
            for cache_key, permission_names in self._group_permission_names_cache.items()
            if cache_key.startswith(prefix)
        }

    def _render_members_cards(self, members: List[dict]) -> None:
        """Render the member list by reusing card widgets instead of recreating them."""
        if self._member_empty_label is None or not self._member_empty_label.winfo_exists():
            self._member_empty_label = ctk.CTkLabel(
                self.members_list,
                text="No members found.",
                text_color="#a0a0a0",
            )

        if not members:
            empty_text = "No matching members found." if (self.member_search_var.get() or "").strip() else "No members found."
            self._member_empty_label.configure(text=empty_text)
            if not self._member_empty_label.winfo_manager():
                self._member_empty_label.pack(anchor="w", pady=6)
            self._hide_unused_member_cards(0)
            return

        if self._member_empty_label.winfo_manager():
            self._member_empty_label.pack_forget()

        account_id = self.selected_account_id.get().strip()
        for index, member in enumerate(members):
            card_widgets = self._ensure_member_card(index)
            self._populate_member_card(card_widgets, account_id, member)

        self._hide_unused_member_cards(len(members))

    def _ensure_member_card(self, index: int) -> Dict[str, Any]:
        """Create a reusable member card slot when the pool needs to grow."""
        while len(self._member_card_pool) <= index:
            card = ctk.CTkFrame(self.members_list, fg_color="#111111", corner_radius=10)

            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=12, pady=(10, 2))

            left = ctk.CTkFrame(top, fg_color="transparent")
            left.pack(side="left", fill="x", expand=True)

            email_label = ctk.CTkLabel(left, text="", text_color="#ffffff", font=("Segoe UI", 13, "bold"))
            email_label.pack(anchor="w")

            status_label = ctk.CTkLabel(left, text="", text_color="#4ec9b0", font=("Segoe UI", 11))
            status_label.pack(anchor="w")

            action_var = tk.StringVar(value="Actions")
            card_widgets: Dict[str, Any] = {
                "card": card,
                "action_var": action_var,
                "member_id": "",
                "email": "",
                "email_label": email_label,
                "status_label": status_label,
            }

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
                command=lambda choice, data=card_widgets: self._on_member_card_action(data, choice),
            )
            action_combo.pack(side="right")

            member_id_label = ctk.CTkLabel(card, text="", text_color="#a0a0a0", font=("Segoe UI", 11))
            member_id_label.pack(anchor="w", padx=12, pady=(0, 2))

            roles_label = ctk.CTkLabel(
                card,
                text="",
                text_color="#a0a0a0",
                font=("Segoe UI", 11),
                wraplength=900,
                justify="left",
            )
            roles_label.pack(anchor="w", padx=12, pady=(0, 10))

            card_widgets["action_combo"] = action_combo
            card_widgets["member_id_label"] = member_id_label
            card_widgets["roles_label"] = roles_label
            self._member_card_pool.append(card_widgets)

        return self._member_card_pool[index]

    def _populate_member_card(self, card_widgets: Dict[str, Any], account_id: str, member: dict) -> None:
        """Update one pooled member card with the latest member data."""
        user = member.get("user") or {}
        email = user.get("email", "(no email)")
        status = member.get("status", "")
        member_id = member.get("id", "")

        permissions_text = ""
        group_permissions = self._member_permissions_summary(account_id, member)
        if group_permissions:
            permissions_text = ", " + group_permissions

        roles = member.get("roles") or []
        role_names = [role.get("name", "") for role in roles if isinstance(role, dict)]
        roles_text = ", ".join([role_name for role_name in role_names if role_name]) or "(no roles)"
        roles_text += permissions_text

        card_widgets["member_id"] = member_id
        card_widgets["email"] = email
        card_widgets["email_label"].configure(text=email)
        card_widgets["status_label"].configure(text=status)
        card_widgets["member_id_label"].configure(text=f"Member ID: {member_id}")
        card_widgets["roles_label"].configure(text=f"Roles: {roles_text}")
        card_widgets["action_var"].set("Actions")

        card = card_widgets["card"]
        if not card.winfo_manager():
            card.pack(fill="x", padx=6, pady=6)

    def _hide_unused_member_cards(self, start_index: int) -> None:
        """Hide any pooled member cards that are not needed for the current view."""
        for card_widgets in self._member_card_pool[start_index:]:
            card = card_widgets["card"]
            if card.winfo_manager():
                card.pack_forget()

    def _on_member_card_action(self, card_widgets: Dict[str, Any], choice: str) -> None:
        """Dispatch a member-card action and then reset the action chooser."""
        if choice != "Actions":
            self._handle_member_action(choice, card_widgets["member_id"], card_widgets["email"])
        card_widgets["action_var"].set("Actions")

    def _load_group_members_async(self, group_id: str, label_widget: ctk.CTkLabel) -> None:
        """Load group members in the background and update the card label."""
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
        """Format a compact inline list of member emails."""
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
        """Render the group list as cards with member and permission details."""
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
        """Load one group's permissions in the background for the group card UI."""
        if not account_id or not group_id:
            label_widget.configure(text="Permissions: (unavailable)")
            return

        def worker():
            try:
                cf = self._client_for("groups_read")
                resp = cf.get_user_group(account_id, group_id)
                group_detail = resp.get("result") or {}

                permissions_text = self.permission_service.format_group_permissions(group_detail)
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

    def scan_all_members(self):
        """Scan all members, batch uncached risk profiles, and render grouped results."""
        existing_scan_window = getattr(self, "_scan_window", None)
        if existing_scan_window is not None and existing_scan_window.winfo_exists():
            existing_scan_window.lift()
            existing_scan_window.focus_force()
            return

        account_id = self.selected_account_id.get().strip()
        if not account_id:
            messagebox.showerror("Error", "Select an account first.", parent=self)
            return

        members = list(self._all_members) if self._members_loaded_account_id == account_id else None
        groups = list(self._all_groups) if self._groups_loaded_account_id == account_id else None

        if members is None or groups is None:
            try:
                if members is None:
                    members = self._client_for("members_read").list_members(account_id).get("result") or []
                    self._set_members(members, account_id)
                if groups is None:
                    groups = self._client_for("groups_read").list_user_groups(account_id).get("result") or []
                    self._set_groups(groups, account_id)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load scan data:\n\n{e}", parent=self)
                return

        win, scan_status_var, output = self.open_scan_window()

        def worker():
            self._ui(self._set_scan_status, scan_status_var, "Loading members and groups...")
            group_names: List[str] = []
            grouped_results: Dict[str, List[dict]] = {}
            errors: List[str] = []
            member_scan_inputs: List[dict] = []
            scan_requests: Dict[str, dict] = {}
            parsed_risk_cache: Dict[str, dict] = {}
            local_prefill_by_cache_key: Dict[str, dict] = {}
            cached_hits = 0
            local_fast_path_hits = 0

            for group in groups:
                if not isinstance(group, dict):
                    continue
                group_name = (group.get("name") or "").strip()
                if not group_name or group_name in grouped_results:
                    continue
                group_names.append(group_name)
                grouped_results[group_name] = []

            self._ui(self._set_scan_status, scan_status_var, "Loading group permissions...")
            group_permissions_by_id, permission_errors = self.permission_service.build_group_permissions_cache(
                account_id,
                members,
                self._client_for,
                cached_permissions_by_id=self._cached_group_permissions_for_account(account_id),
            )
            for group_id, permission_names in group_permissions_by_id.items():
                self._group_permission_names_cache[f"{account_id}:{group_id}"] = list(permission_names)
            errors.extend(permission_errors)

            for m in members:
                try:
                    user = m.get("user") or {}
                    email = user.get("email", "(no email)")
                    member_id = (m.get("id") or "").strip() or email

                    # roles
                    roles_text = self.permission_service.get_full_member_permissions(
                        account_id,
                        m,
                        self._client_for,
                        group_permissions_by_id,
                    )

                    # group
                    member_group_names = self._member_group_names(m)
                    group_name = ", ".join(member_group_names) or "Other"
                    cache_key = self.scan_service.scan_profile_key(group_name, roles_text)

                    cached_result = self._risk_scan_cache.get(cache_key)
                    if cached_result and not self.scan_service.is_rate_limited(cached_result.get("raw")):
                        parsed_risk_cache[cache_key] = cached_result
                        cached_hits += 1
                    elif cache_key not in scan_requests:
                        self._risk_scan_cache.pop(cache_key, None)
                        local_scan = self.scan_service.prepare_local_scan(roles_text)
                        local_prefill_by_cache_key[cache_key] = local_scan["prefill"]
                        if local_scan["resolved_locally"]:
                            parsed_risk_cache[cache_key] = local_scan["prefill"]
                            self._risk_scan_cache[cache_key] = local_scan["prefill"]
                            local_fast_path_hits += 1
                        else:
                            scan_requests[cache_key] = {
                                "email": email,
                                "member_id": member_id,
                                "group_name": group_name,
                                "roles_text": roles_text,
                                "candidate_roles_text": ", ".join(local_scan["unresolved_permissions"]),
                            }

                    member_scan_inputs.append(
                        {
                            "email": email,
                            "member_id": member_id,
                            "groups": member_group_names or ["Other"],
                            "cache_key": cache_key,
                        }
                    )

                except Exception as e:
                    errors.append(str(e))

            self._ui(
                self._append_scan_text,
                output,
                (
                    f"Loaded {len(members)} members, {len(group_permissions_by_id)} groups, "
                    f"{cached_hits} cached profiles, {local_fast_path_hits} locally resolved profiles, "
                    f"and {len(scan_requests)} unresolved model evaluations.\n"
                ),
                "scan_muted",
            )

            self._ui(
                self._set_scan_status,
                scan_status_var,
                f"Scanning {len(scan_requests)} unresolved risk profiles..."
            )

            if scan_requests:
                try:
                    batch_results = self.scan_service.scan_member_risks_batch(
                        scan_requests,
                        status_callback=lambda text: self._ui(self._set_scan_status, scan_status_var, text),
                    )
                    for cache_key, parsed_result in batch_results.items():
                        merged_result = self.scan_service.merge_scan_results(
                            local_prefill_by_cache_key.get(cache_key, self.scan_service.default_scan_result()),
                            parsed_result,
                        )
                        parsed_risk_cache[cache_key] = merged_result
                        self._risk_scan_cache[cache_key] = merged_result
                except Exception as e:
                    errors.append(f"Batched risk scan failed: {e}")

            for member_input in member_scan_inputs:
                parsed_result = parsed_risk_cache.get(member_input["cache_key"])
                if parsed_result is None:
                    continue

                for target_group in member_input["groups"]:
                    if target_group not in grouped_results:
                        group_names.append(target_group)
                        grouped_results[target_group] = []
                    grouped_results[target_group].append(
                        {"email": member_input["email"], "risk": parsed_result}
                    )

            self._ui(self._render_grouped_scan_results, output, group_names, grouped_results, errors)
            self._ui(self._set_scan_status, scan_status_var, "Scan complete.")

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
        existing_scan_window = getattr(self, "_scan_window", None)
        if existing_scan_window is not None and existing_scan_window.winfo_exists():
            existing_scan_window.lift()
            existing_scan_window.focus_force()
            return

        if self._refresh_cooldown:
            return

        self._refresh_cooldown = True
        if hasattr(self, "refresh_button"):
            self.refresh_button.configure(state="disabled", text="Refresh Now (5s)")

            # optional countdown text
            for i in range(1, 5):
                self.after(
                    i * 1000,
                    lambda remaining=5 - i: (
                            self.refresh_button.winfo_exists()
                            and self.refresh_button.configure(text=f"Refresh Now ({remaining}s)")
                    ),
                )

        self.after(5000, self._reenable_refresh_button)

        def do():
            account_id = self.selected_account_id.get().strip()
            if not account_id:
                raise ValueError("Select an account first.")

            members = self._client_for("members_read").list_members(account_id).get("result") or []
            groups = self._client_for("groups_read").list_user_groups(account_id).get("result") or []

            self._ui(self._set_members, members, account_id)
            self._ui(self._set_groups, groups, account_id)
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
                self._ui(self._set_members, members, account_id)
            except Exception as e:
                if self._is_network_error(e):
                    network_failed = True
                self._ui(self._append, f"[AUTO-REFRESH ERROR][members] {repr(e)}")

            try:
                groups = self._client_for("groups_read").list_user_groups(account_id).get("result") or []
                self._ui(self._set_groups, groups, account_id)
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
