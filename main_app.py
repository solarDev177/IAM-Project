# Cloudflare IAM Explorer
# main app

import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from tkinter import filedialog, messagebox, simpledialog, ttk
import customtkinter as ctk
import time

from api_handler import CloudflareAPIError
from requests.exceptions import ConnectionError, Timeout
from typing import Optional, Callable, Any, Dict, List, Set, Tuple, cast
try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    Image = None
    ImageDraw = None
    ImageFont = None

from cloudflare_client import CloudflareClient
from permission_service import GroupPermissionService
from runtime_log import append_runtime_log, clear_runtime_log, runtime_log_path
from scan_service import RiskScanService
from token_manager import TokenManagerWindow
from token_store import TokenStore
from window_icon import WindowIconManager


class App(ctk.CTkToplevel):
    def __init__(self, master, account_id: str):
        super().__init__(master)
        append_runtime_log("App.__init__", f"Main app initialization starting for account {account_id}.")
        self.title("Cloudflare IAM Explorer")
        self.geometry("1920x1080")
        WindowIconManager.apply(self)
        try:
            self.deiconify()
            self.state("normal")
            self.lift()
            self.focus_force()
            self.attributes("-topmost", True)
            self.after(180, lambda: self.winfo_exists() and self.attributes("-topmost", False))
        except Exception:
            pass

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.configure(fg_color="#000000")

        # anti-spam:
        self._refresh_cooldown = False

        # Core state
        self.initial_account_id = account_id
        self.selected_account_id = tk.StringVar(value=account_id)
        self.show_account_id = tk.BooleanVar(value=False)
        self._account_label_to_id: Dict[str, str] = {}
        self._account_id_to_label: Dict[str, str] = {}

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
        self._member_permission_fetch_inflight: Set[str] = set()
        self._all_members: List[dict] = []
        self._all_groups: List[dict] = []
        self._members_loaded_account_id: Optional[str] = None
        self._groups_loaded_account_id: Optional[str] = None
        self._member_card_pool: List[Dict[str, Any]] = []
        self._member_empty_label = None
        self._member_filter_job = None
        self._scan_window = None
        self._scan_chart_window = None
        self._scan_chart_button = None
        self._scan_status_label = None
        self._scan_stats_summary_label = None
        self._scan_stats_detail_label = None
        self._scan_stats_detail_box = None
        self._scan_stats_members_frame = None
        self._scan_chart_loading_frame = None
        self._scan_chart_progress = None
        self._scan_chart_progress_label = None
        self._scan_tree = None
        self._scan_results_summary_label = None
        self._scan_results_frame = None
        self.status_label = None
        self.member_results_label = None
        self._last_scan_permission_counts: Optional[Dict[str, int]] = None
        self._last_scan_group_counts: Optional[Dict[str, int]] = None
        self._last_scan_critical_members: List[str] = []
        self._last_scan_members_by_severity: Dict[str, List[Dict[str, Any]]] = {
            "Low": [],
            "Medium": [],
            "High": [],
            "Critical": [],
        }
        self._last_scan_group_members_by_severity: Dict[str, List[Dict[str, Any]]] = {
            "Low": [],
            "Medium": [],
            "High": [],
            "Critical": [],
        }
        self._auto_refresh_paused_for_scan = False
        self._external_scan_consent_granted = False
        self._privacy_notice_shown = False
        self._data_notice_window = None
        self._members_signature = None
        self._groups_signature = None
        self.member_search_var = tk.StringVar(value="")
        self.member_results_var = tk.StringVar(value="No members loaded")
        self.permission_service = GroupPermissionService()
        self.scan_service = RiskScanService()
        self._action_buttons: List[Any] = []
        self._action_buttons_container = None
        self._action_buttons_last_columns = 0

        # Auto-refresh
        self._refresh_interval_ms = 300_000
        self._refresh_inflight = False
        self._refresh_job = None
        self._last_groups_error = None
        self._last_members_error = None

        # Backoff:
        self._net_failures = 0
        self._max_backoff_ms = 120_000  # cap at 2 minutes

        self._build_ui()
        self._animate_window_fade_in(self, duration_ms=260, steps=14)

        # Start with one immediate refresh, then fall back to the background cadence.
        self._after_call(180, self._present_initial_data_notice)
        self._after_call(250, lambda: self.refresh_now(force=True, reason="Initial refresh"))
        self._after_call(500, lambda: self.start_auto_refresh(self._refresh_interval_ms))
        self._last_groups_error = None

        # Stop refresh on close
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        append_runtime_log("App.__init__", "Main app initialization completed.")

    # ---------------- UI ----------------
    def _build_ui(self):
        self._dashboard_scroll = ctk.CTkScrollableFrame(
            self,
            fg_color="#000000",
            corner_radius=0,
            scrollbar_button_color="#2a2a2a",
            scrollbar_button_hover_color="#3a3a3a",
        )
        self._dashboard_scroll.pack(fill="both", expand=True, padx=0, pady=0)

        # Top bar
        top = ctk.CTkFrame(self._dashboard_scroll, fg_color="#000000")
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
            button_color="#ff8c1a",
            button_hover_color="#ff9f1c",
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
            fg_color="#ff8c1a",
            hover_color="#ff9f1c",
            text_color="#ffffff",
        ).grid(row=0, column=4, padx=(8, 0), sticky="w")

        top.columnconfigure(3, weight=1)

        # Buttons row
        btns = ctk.CTkFrame(self._dashboard_scroll, fg_color="#000000")
        btns.pack(fill="x", padx=12, pady=(0, 10))
        action_grid = ctk.CTkFrame(btns, fg_color="transparent")
        action_grid.pack(fill="x")
        self._action_buttons_container = action_grid

        button_specs = [
            ("Verify Token", self.on_verify, "#ff8c1a", "#ff9f1c", "verify_button"),
            ("List Accounts", self.on_list_accounts, "#ff8c1a", "#ff9f1c", None),
            ("Add Member", self.add_member, "#ff8c1a", "#ff9f1c", None),
            ("List Roles", self.on_list_roles, "#ff8c1a", "#ff9f1c", None),
            ("Create User Group", self.create_group, "#ff8c1a", "#ff9f1c", None),
            ("Refresh Now", self.refresh_now, "#ff8c1a", "#ff9f1c", "refresh_button"),
            ("Manage Tokens", self.open_token_manager, "#333333", "#444444", None),
            ("Data Notice", self.show_data_notice, "#333333", "#444444", None),
            ("Clear Local Data", self.clear_local_data, "#333333", "#444444", None),
            ("Launch Scan", self.scan_all_members, "#333333", "#444444", "scan_button"),
        ]

        self._action_buttons = []
        for text, command, fg_color, hover_color, attr_name in button_specs:
            button = ctk.CTkButton(
                action_grid,
                text=text,
                command=command,
                fg_color=fg_color,
                hover_color=hover_color,
                width=170,
            )
            if attr_name:
                setattr(self, attr_name, button)
            self._action_buttons.append(button)

        self._layout_action_buttons()
        btns.bind("<Configure>", lambda _event: self._layout_action_buttons())

        # Account chooser + status
        mid = ctk.CTkFrame(self._dashboard_scroll, fg_color="#000000")
        mid.pack(fill="x", padx=12, pady=(0, 10))

        ctk.CTkLabel(mid, text="Selected account:", text_color="#ffffff").grid(
            row=0, column=0, sticky="w", padx=(0, 6)
        )

        self.account_combo = ctk.CTkComboBox(
            mid,
            values=[self._format_account_choice_label("Selected", self.initial_account_id)],
            state="readonly",
            width=520,
            fg_color="#1a1a1a",
            button_color="#ff8c1a",
            button_hover_color="#ff9f1c",
            border_color="#333333",
            command=self._on_account_choice,
        )
        self.account_combo.grid(row=0, column=1, sticky="w", padx=(0, 12))
        ctk.CTkCheckBox(
            mid,
            text="Show",
            variable=self.show_account_id,
            command=self._refresh_account_combo_display,
            width=80,
            fg_color="#ff8c1a",
            hover_color="#ff9f1c",
            text_color="#ffffff",
        ).grid(row=0, column=2, padx=(0, 12), sticky="w")
        self._refresh_account_combo_display()

        self.status_var = tk.StringVar(value="Ready.")
        self.status_label = ctk.CTkLabel(
            mid,
            textvariable=self.status_var,
            text_color="#ff9f1c",
            justify="left",
            anchor="w",
            wraplength=640,
        )
        self.status_label.grid(row=1, column=0, columnspan=4, sticky="we", pady=(8, 0))
        mid.grid_columnconfigure(1, weight=1)
        mid.grid_columnconfigure(3, weight=1)

        # Tabs
        live = ctk.CTkFrame(self._dashboard_scroll, fg_color="#000000")
        live.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self.tabs = ctk.CTkTabview(
            live,
            fg_color="#000000",
            segmented_button_fg_color="#333333",
            segmented_button_selected_color="#ff8c1a",
            segmented_button_selected_hover_color="#ff9f1c",
            segmented_button_unselected_color="#555555",
            segmented_button_unselected_hover_color="#666666",
            text_color="#ffffff",
            text_color_disabled="#a0a0a0",
        )
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

        self.member_results_label = ctk.CTkLabel(
            members_toolbar,
            textvariable=self.member_results_var,
            text_color="#ff9f1c",
        )
        self.member_results_label.pack(side="right")

        members_section = ctk.CTkFrame(members_tab, fg_color="#111111", corner_radius=12)
        members_section.pack(fill="x", padx=10, pady=10)
        members_header = ctk.CTkFrame(members_section, fg_color="transparent")
        members_header.pack(fill="x", padx=12, pady=(12, 8))
        ctk.CTkLabel(
            members_header,
            text="Members",
            text_color="#ffffff",
            font=("Segoe UI", 14, "bold"),
        ).pack(side="left", anchor="w")
        self._members_section_chevron = tk.StringVar(value="▾")
        self._members_section_body = ctk.CTkFrame(members_section, fg_color="transparent")
        toggle_members_button = ctk.CTkButton(
            members_header,
            textvariable=self._members_section_chevron,
            width=32,
            height=28,
            fg_color="#ff8c1a",
            hover_color="#ff9f1c",
            text_color="#ffffff",
            font=("Segoe UI", 12, "bold"),
            corner_radius=999,
            command=self._toggle_members_section,
        )
        toggle_members_button.pack(side="right")
        self._members_section_body.pack(fill="x", padx=0, pady=(0, 0))

        self.members_list = ctk.CTkFrame(self._members_section_body, fg_color="#000000")
        self.members_list.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.groups_list = ctk.CTkFrame(groups_tab, fg_color="#000000")
        self.groups_list.pack(fill="both", expand=True, padx=10, pady=10)

        # Log
        bottom = ctk.CTkFrame(self._dashboard_scroll, fg_color="#000000")
        bottom.pack(fill="x", padx=12, pady=(0, 12))

        ctk.CTkLabel(bottom, text="Log:", text_color="#ffffff").pack(anchor="w")
        self.output = ctk.CTkTextbox(
            bottom, height=120, wrap="none",
            fg_color="#1a1a1a", border_color="#333333", text_color="#ffffff"
        )
        self.output.pack(fill="x", expand=False, pady=(6, 0))

        self._load_selected_token_into_entry()
        self.member_search_var.trace_add("write", self._on_member_search_changed)

    def _present_initial_data_notice(self) -> None:
        """Show the data-handling notice once per app session after the dashboard appears."""
        if self._privacy_notice_shown or not self.winfo_exists():
            return
        self._privacy_notice_shown = True
        self.show_data_notice(title="Data Handling Notice")

    def _data_notice_text(self) -> str:
        """Describe the app's local storage, external sharing, and user cleanup controls."""
        token_path = self.store.path()
        log_path = runtime_log_path()
        return (
            "This app stores and processes a small amount of IAM-related data on this device.\n\n"
            "Local data stored on this device:\n"
            f"- Encrypted Cloudflare API tokens in:\n  {token_path}\n"
            "- The encryption key for those tokens in the system keyring.\n"
            "- An optional local login PIN as a salted PBKDF2 hash in the system keyring.\n"
            f"- Runtime diagnostics in:\n  {log_path}\n"
            "- Member, group, and scan caches in memory while this app is open.\n\n"
            "External sharing:\n"
            "- Vulnerability scans ask for your consent before sending unresolved permission names to an external AI service.\n"
            "- The external scan path minimizes payloads and avoids sending full member and group context when possible.\n\n"
            "Retention and control:\n"
            "- Saved tokens and runtime logs remain on this device until you remove them.\n"
            "- Session caches are cleared when the app closes, and you can clear local app data manually at any time.\n"
            "- Use 'Clear Local Data' to remove saved encrypted tokens, the runtime log, and cached session data from this device."
        )

    def show_data_notice(self, title: str = "Data Handling Notice") -> None:
        """Open a reusable data-handling notice window for transparency and review."""
        existing = self._data_notice_window
        if existing is not None and existing.winfo_exists():
            existing.title(title)
            existing.lift()
            existing.focus_force()
            return

        win = ctk.CTkToplevel(self)
        win.title(title)
        win.geometry("760x560")
        win.configure(fg_color="#000000")
        WindowIconManager.apply(win)
        self._data_notice_window = win
        try:
            win.transient(self)
            win.deiconify()
            win.lift()
            win.focus_force()
            win.attributes("-topmost", True)
            win.after(220, lambda: win.winfo_exists() and win.attributes("-topmost", False))
        except Exception:
            pass

        shell = ctk.CTkFrame(win, fg_color="#111111", corner_radius=12)
        shell.pack(fill="both", expand=True, padx=18, pady=18)

        ctk.CTkLabel(
            shell,
            text=title,
            text_color="#ffffff",
            font=("Segoe UI", 22, "bold"),
        ).pack(anchor="w", padx=18, pady=(18, 8))

        ctk.CTkLabel(
            shell,
            text="This summary explains what the app stores locally, what can leave the device, and how to clear it.",
            text_color="#d0d0d0",
            justify="left",
            anchor="w",
            wraplength=680,
        ).pack(fill="x", padx=18, pady=(0, 10))

        body = ctk.CTkTextbox(
            shell,
            fg_color="#0a0a0a",
            border_color="#333333",
            text_color="#f0f0f0",
            wrap="word",
            font=("Segoe UI", 12),
        )
        body.pack(fill="both", expand=True, padx=18, pady=(0, 14))
        body.insert("1.0", self._data_notice_text())
        body.configure(state="disabled")

        actions = ctk.CTkFrame(shell, fg_color="transparent")
        actions.pack(fill="x", padx=18, pady=(0, 18))

        ctk.CTkButton(
            actions,
            text="Clear Local Data",
            command=self.clear_local_data,
            fg_color="#333333",
            hover_color="#444444",
            width=150,
        ).pack(side="left")

        ctk.CTkButton(
            actions,
            text="Close",
            command=lambda: self._close_data_notice_window(win),
            fg_color="#ff8c1a",
            hover_color="#ff9f1c",
            width=120,
        ).pack(side="right")

        win.protocol("WM_DELETE_WINDOW", lambda: self._close_data_notice_window(win))
        self._animate_window_fade_in(win, duration_ms=180, steps=10)

    def _close_data_notice_window(self, win: Any) -> None:
        """Close the reusable data-notice window safely."""
        if self._data_notice_window is win:
            self._data_notice_window = None
        if win is not None and win.winfo_exists():
            win.destroy()

    def _layout_action_buttons(self) -> None:
        """Wrap the main action buttons into multiple rows when the window gets narrow."""
        container = self._action_buttons_container
        if container is None or not container.winfo_exists():
            return

        container.update_idletasks()
        available_width = max(container.winfo_width(), self.winfo_width() - 48, 320)
        min_button_width = 178
        columns = max(1, min(len(self._action_buttons), available_width // min_button_width))
        if columns == self._action_buttons_last_columns and any(button.winfo_manager() == "grid" for button in self._action_buttons):
            return

        self._action_buttons_last_columns = columns
        for index in range(max(len(self._action_buttons), 6)):
            container.grid_columnconfigure(index, weight=0, uniform="")
        for column in range(columns):
            container.grid_columnconfigure(column, weight=1, uniform="action-btn")

        for index, button in enumerate(self._action_buttons):
            row = index // columns
            column = index % columns
            button.grid(row=row, column=column, sticky="ew", padx=4, pady=4)

    def _toggle_members_section(self) -> None:
        """Expand or collapse the member-card section inside the Members tab."""
        body = getattr(self, "_members_section_body", None)
        chevron = getattr(self, "_members_section_chevron", None)
        if body is None or chevron is None or not body.winfo_exists():
            return

        if body.winfo_manager():
            body.pack_forget()
            chevron.set("▸")
        else:
            body.pack(fill="x", padx=0, pady=(0, 0))
            chevron.set("▾")

    # ---------------- UI helpers ----------------
    @staticmethod
    def _hex_to_rgb(color: str) -> Tuple[int, int, int]:
        """Convert a hex color string into an RGB tuple."""
        cleaned = (color or "#000000").lstrip("#")
        if len(cleaned) != 6:
            return 0, 0, 0
        return (
            int(cleaned[0:2], 16),
            int(cleaned[2:4], 16),
            int(cleaned[4:6], 16),
        )

    @staticmethod
    def _rgb_to_hex(rgb: Tuple[int, int, int]) -> str:
        """Convert an RGB tuple into a hex color string."""
        return "#{:02x}{:02x}{:02x}".format(*rgb)

    def _blend_hex(self, start_color: str, end_color: str, ratio: float) -> str:
        """Blend two hex colors together by the provided ratio."""
        start_rgb = self._hex_to_rgb(start_color)
        end_rgb = self._hex_to_rgb(end_color)
        blend_ratio = max(0.0, min(1.0, ratio))
        blended: Tuple[int, int, int] = (
            round(start_rgb[0] + ((end_rgb[0] - start_rgb[0]) * blend_ratio)),
            round(start_rgb[1] + ((end_rgb[1] - start_rgb[1]) * blend_ratio)),
            round(start_rgb[2] + ((end_rgb[2] - start_rgb[2]) * blend_ratio)),
        )
        return self._rgb_to_hex(blended)

    def _after_call(self, delay_ms: int, callback: Callable[[], None]) -> str:
        """Schedule a zero-argument callback while keeping type checking simple."""
        return cast(Any, self).after(delay_ms, callback)

    @staticmethod
    def _start_daemon_thread(callback: Callable[[], None]) -> None:
        """Run a callback on a daemon thread."""
        threading.Thread(target=callback, daemon=True).start()

    def _run_bg_worker(self, label: str, func: Callable[[], Any]) -> None:
        """Execute one background action and report the result on the UI thread."""
        try:
            result = func()
            self._ui(self._on_success, label, result)
        except Exception as err:
            self._ui(self._on_error, label, err)

    @staticmethod
    def _invoke(callable_obj: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Invoke a callable with the supplied arguments."""
        return callable_obj(*args, **kwargs)

    def _animate_window_fade_in(self, window: Any, duration_ms: int = 220, steps: int = 12) -> None:
        """Show a toplevel window immediately without alpha animation."""
        if window is None or not window.winfo_exists():
            return

        existing_job = getattr(window, "_fade_job", None)
        if existing_job:
            try:
                self.after_cancel(existing_job)
            except tk.TclError:
                pass
        window._fade_job = None
        try:
            window.attributes("-alpha", 1.0)
        except tk.TclError:
            pass

    def _animate_window_fade_step(self, window: Any, delay: int, steps: int, index: int) -> None:
        """Advance one fade-in step for a toplevel window."""
        if not window.winfo_exists():
            return
        alpha = min(1.0, index / max(steps, 1))
        try:
            window.attributes("-alpha", alpha)
        except tk.TclError:
            return
        if index < steps:
            window._fade_job = self._after_call(
                delay,
                partial(self._animate_window_fade_step, window, delay, steps, index + 1),
            )
        else:
            window._fade_job = None

    def _animate_widget_color(
        self,
        widget: Any,
        option: str,
        start_color: str,
        end_color: str,
        duration_ms: int = 180,
        steps: int = 8,
        on_complete: Optional[Callable[[], None]] = None,
    ) -> None:
        """Animate a widget color option between two hex colors."""
        if widget is None or not widget.winfo_exists():
            return

        job_attr = f"_{option}_animation_job"
        existing_job = getattr(widget, job_attr, None)
        if existing_job:
            try:
                self.after_cancel(existing_job)
            except tk.TclError:
                pass

        delay = max(10, duration_ms // max(steps, 1))
        self._animate_widget_color_step(
            widget,
            option,
            start_color,
            end_color,
            delay,
            steps,
            0,
            job_attr,
            on_complete,
        )

    def _animate_widget_color_step(
        self,
        widget: Any,
        option: str,
        start_color: str,
        end_color: str,
        delay: int,
        steps: int,
        index: int,
        job_attr: str,
        on_complete: Optional[Callable[[], None]],
    ) -> None:
        """Advance one animated color step for a widget option."""
        if not widget.winfo_exists():
            return
        ratio = index / max(steps, 1)
        widget.configure(**{option: self._blend_hex(start_color, end_color, ratio)})
        if index < steps:
            setattr(
                widget,
                job_attr,
                self._after_call(
                    delay,
                    partial(
                        self._animate_widget_color_step,
                        widget,
                        option,
                        start_color,
                        end_color,
                        delay,
                        steps,
                        index + 1,
                        job_attr,
                        on_complete,
                    ),
                ),
            )
            return

        setattr(widget, job_attr, None)
        if on_complete is not None:
            on_complete()

    def _flash_label_text(self, label: Any, base_color: str = "#ff9f1c", accent_color: str = "#ffbf69") -> None:
        """Briefly brighten a label to make updates feel more responsive."""
        if label is None or not label.winfo_exists():
            return
        self._animate_widget_color(
            label,
            "text_color",
            base_color,
            accent_color,
            duration_ms=90,
            steps=4,
            on_complete=partial(
                self._animate_widget_color,
                label,
                "text_color",
                accent_color,
                base_color,
                220,
                9,
            ),
        )

    def _animate_card_entry(
        self,
        card: Any,
        accent_color: str = "#16324f",
        base_color: str = "#111111",
        duration_ms: int = 260,
        delay_ms: int = 0,
    ) -> None:
        """Wash a card in with a subtle accent tint when it appears or changes."""
        if card is None or not card.winfo_exists():
            return

        pending_job = getattr(card, "_entry_animation_delay_job", None)
        if pending_job:
            try:
                self.after_cancel(pending_job)
            except tk.TclError:
                pass

        if delay_ms > 0:
            card._entry_animation_delay_job = self._after_call(
                delay_ms,
                partial(
                    self._animate_widget_color,
                    card,
                    "fg_color",
                    accent_color,
                    base_color,
                    duration_ms,
                    10,
                ),
            )
        else:
            self._animate_widget_color(card, "fg_color", accent_color, base_color, duration_ms=duration_ms, steps=10)

    def _set_status(self, text: str):
        self.status_var.set(text)
        if self.status_label is not None and self.status_label.winfo_exists():
            wrap = max(self.winfo_width() - 120, 220)
            self.status_label.configure(wraplength=wrap)
        self._flash_label_text(self.status_label)

    @staticmethod
    def _fit_label_to_parent_width(label_widget: Any, horizontal_padding: int = 32, min_width: int = 220) -> None:
        """Set a label wrap length from its parent's current width."""
        if label_widget is None or not label_widget.winfo_exists():
            return
        parent = label_widget.master
        if parent is None or not parent.winfo_exists():
            return
        parent.update_idletasks()
        label_widget.configure(wraplength=max(parent.winfo_width() - horizontal_padding, min_width))

    @staticmethod
    def _set_scroll_text_content(text_widget: Any, text: str) -> None:
        """Replace the content of a one-line horizontal-scroll text strip."""
        if text_widget is None or not text_widget.winfo_exists():
            return
        text_widget.configure(state="normal")
        text_widget.delete("1.0", "end")
        text_widget.insert("1.0", text or "")
        text_widget.configure(state="disabled")
        text_widget.xview_moveto(0)

    def _create_horizontal_scroll_text(
        self,
        parent: Any,
        text: str,
        *,
        fg_color: str,
        text_color: str,
        font: Any = ("Segoe UI", 11),
        height: int = 1,
        padx: Tuple[int, int] = (0, 0),
        pady: Tuple[int, int] = (0, 0),
    ) -> Tuple[Any, Any]:
        """Create a compact horizontally scrollable text strip."""
        host = ctk.CTkFrame(parent, fg_color="transparent")
        host.pack(fill="x", padx=padx, pady=pady)

        text_widget = tk.Text(
            host,
            height=height,
            wrap="none",
            bg=fg_color,
            fg=text_color,
            insertbackground=text_color,
            relief="flat",
            borderwidth=0,
            highlightthickness=0,
            font=font,
            padx=0,
            pady=0,
        )
        text_widget.pack(fill="x")

        scrollbar = ctk.CTkScrollbar(
            host,
            orientation="horizontal",
            command=text_widget.xview,
            fg_color="transparent",
            button_color="#333333",
            button_hover_color="#555555",
            height=12,
        )
        scrollbar.pack(fill="x", pady=(2, 0))
        text_widget.configure(xscrollcommand=scrollbar.set)

        self._set_scroll_text_content(text_widget, text)
        return host, text_widget

    def _refresh_scan_stats_header_strip(self, scan_window: Any) -> None:
        """Update the scan stats header strip using the latest summary and helper text."""
        if scan_window is None or not scan_window.winfo_exists():
            return
        header_strip = self._scan_stats_summary_label
        if header_strip is None or not header_strip.winfo_exists():
            return

        summary_var = getattr(scan_window, "_scan_stats_summary_var", None)
        summary_text = summary_var.get() if summary_var is not None else ""
        hint_text = str(getattr(scan_window, "_scan_stats_hint_text", "") or "").strip()
        combined = summary_text.strip()
        if hint_text:
            combined = f"{combined}\n{hint_text}" if combined else hint_text
        self._set_scroll_text_content(header_strip, combined)

    def _update_group_card_detail_strip(
        self,
        text_widget: Any,
        *,
        users_text: Optional[str] = None,
        permissions_text: Optional[str] = None,
    ) -> None:
        """Update one group card's shared detail strip while preserving the other line."""
        if text_widget is None or not text_widget.winfo_exists():
            return
        if users_text is not None:
            text_widget._group_users_text = users_text
        if permissions_text is not None:
            text_widget._group_permissions_text = permissions_text

        current_users = getattr(text_widget, "_group_users_text", "Users: loading...")
        current_permissions = getattr(text_widget, "_group_permissions_text", "Permissions: loading...")
        self._set_scroll_text_content(text_widget, f"{current_users}\n{current_permissions}")

    def _reenable_refresh_button(self):
        self._refresh_cooldown = False
        if hasattr(self, "refresh_button"):
            self.refresh_button.configure(state="normal", text="Refresh Now")

    def _append(self, text: str):
        self.output.insert("end", text + "\n")
        self.output.see("end")

    def _ui(self, func: Callable[..., Any], /, *args: Any, **kwargs: Any) -> None:
        """Run a UI update safely on the Tk main thread."""
        self._after_call(0, partial(self._invoke, func, *args, **kwargs))

    def open_scan_window(self):
        """Open the scan results window and pause scan-conflicting controls."""
        scan_master = self.master if self.master is not None else self
        win: Any = ctk.CTkToplevel(scan_master)
        win.title("Vulnerability Scan Results")
        win.geometry("1090x700")
        win.configure(fg_color="#000000")
        WindowIconManager.apply(win)
        try:
            win.lift()
            win.focus_force()
            win.attributes("-topmost", True)
            win.after(150, lambda: win.winfo_exists() and win.attributes("-topmost", False))
        except Exception:
            pass
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

        body_scroll = ctk.CTkScrollableFrame(
            win,
            fg_color="#000000",
            corner_radius=0,
            scrollbar_button_color="#2a2a2a",
            scrollbar_button_hover_color="#3a3a3a",
        )
        body_scroll.pack(fill="both", expand=True, padx=0, pady=(0, 0))
        win._scan_body_scroll = body_scroll

        controls = ctk.CTkFrame(body_scroll, fg_color="transparent")
        controls.pack(fill="x", padx=16, pady=(0, 8))

        scan_status_var = tk.StringVar(value="Scanning identities...")
        self._scan_status_label = ctk.CTkLabel(
            controls,
            textvariable=scan_status_var,
            text_color="#ff9f1c",
            font=("Segoe UI", 12, "bold")
        )
        self._scan_status_label.pack(side="left")

        self._last_scan_permission_counts = None
        self._last_scan_group_counts = None
        self._last_scan_critical_members = []
        self._last_scan_members_by_severity = {label: [] for label in ("Low", "Medium", "High", "Critical")}
        self._last_scan_group_members_by_severity = {label: [] for label in ("Low", "Medium", "High", "Critical")}

        stats_frame = ctk.CTkFrame(body_scroll, fg_color="#111111", corner_radius=12)
        stats_frame.pack(fill="x", padx=16, pady=(0, 12))

        stats_summary_var = tk.StringVar(value="Scanning identities...")
        ctk.CTkLabel(
            stats_frame,
            text="Scan Summary",
            text_color="#ff9f1c",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", padx=14, pady=(12, 2))
        _summary_host, summary_strip = self._create_horizontal_scroll_text(
            stats_frame,
            "",
            fg_color="#111111",
            text_color="#ff9f1c",
            font=("Segoe UI", 14, "bold"),
            height=2,
            padx=(14, 14),
            pady=(0, 6),
        )
        self._scan_stats_summary_label = summary_strip
        self._scan_stats_hint_label = None
        win._scan_stats_summary_var = stats_summary_var
        win._scan_stats_hint_text = "Click a bar in either chart to inspect direct-member risk or group-derived risk in the tree below."
        self._refresh_scan_stats_header_strip(win)

        chart_loading_frame = ctk.CTkFrame(stats_frame, fg_color="#0b0b0b", corner_radius=10, height=220)
        chart_loading_frame.pack(fill="x", padx=12, pady=(0, 8))
        chart_loading_frame.pack_propagate(False)

        self._scan_chart_progress_label = ctk.CTkLabel(
            chart_loading_frame,
            text="Scanning identities...",
            text_color="#ff9f1c",
            font=("Segoe UI", 14, "bold"),
        )
        self._scan_chart_progress_label.pack(anchor="w", padx=18, pady=(28, 10))

        ctk.CTkLabel(
            chart_loading_frame,
            text="Building scan statistics...",
            text_color="#a0a0a0",
            font=("Segoe UI", 11),
        ).pack(anchor="w", padx=18, pady=(0, 16))

        self._scan_chart_progress = ctk.CTkProgressBar(
            chart_loading_frame,
            mode="indeterminate",
            progress_color="#ff8c1a",
            fg_color="#333333",
            height=12,
        )
        self._scan_chart_progress.pack(fill="x", padx=18, pady=(0, 0))
        self._scan_chart_progress.start()

        charts_frame = ctk.CTkFrame(stats_frame, fg_color="transparent")
        win._scan_charts_frame = charts_frame
        charts_frame.pack(fill="x", pady=(0, 8))
        charts_frame.grid_columnconfigure(0, weight=1, uniform="scan-chart")
        charts_frame.grid_columnconfigure(1, weight=1, uniform="scan-chart")

        direct_chart_frame = ctk.CTkFrame(charts_frame, fg_color="#0b0b0b", corner_radius=10)
        direct_chart_frame.grid(row=0, column=0, sticky="nsew", padx=(12, 6))
        ctk.CTkLabel(
            direct_chart_frame,
            text="Direct Member Permissions",
            text_color="#ffffff",
            font=("Segoe UI", 13, "bold"),
        ).pack(anchor="w", padx=14, pady=(12, 2))
        _direct_subtitle_host, direct_subtitle_label = self._create_horizontal_scroll_text(
            direct_chart_frame,
            "Members counted here have directly assigned permissions in the selected risk bucket.",
            fg_color="#0b0b0b",
            text_color="#a0a0a0",
            font=("Segoe UI", 10),
            padx=(14, 14),
            pady=(0, 6),
        )
        direct_chart_canvas = tk.Canvas(direct_chart_frame, bg="#0b0b0b", highlightthickness=0, height=176)
        direct_chart_canvas.pack(fill="x", padx=12, pady=(0, 12))

        group_chart_frame = ctk.CTkFrame(charts_frame, fg_color="#0b0b0b", corner_radius=10)
        group_chart_frame.grid(row=0, column=1, sticky="nsew", padx=(6, 12))
        ctk.CTkLabel(
            group_chart_frame,
            text="Group-derived Permissions",
            text_color="#ffffff",
            font=("Segoe UI", 13, "bold"),
        ).pack(anchor="w", padx=14, pady=(12, 2))
        _group_subtitle_host, group_subtitle_label = self._create_horizontal_scroll_text(
            group_chart_frame,
            "Members counted here inherit one or more permissions from their Cloudflare groups in the selected risk bucket.",
            fg_color="#0b0b0b",
            text_color="#a0a0a0",
            font=("Segoe UI", 10),
            padx=(14, 14),
            pady=(0, 6),
        )
        group_chart_canvas = tk.Canvas(group_chart_frame, bg="#0b0b0b", highlightthickness=0, height=176)
        group_chart_canvas.pack(fill="x", padx=12, pady=(0, 12))

        win._chart_canvases = {
            "direct": direct_chart_canvas,
            "group": group_chart_canvas,
        }
        win._direct_chart_subtitle_label = direct_subtitle_label
        win._group_chart_subtitle_label = group_subtitle_label
        win._direct_chart_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        win._group_chart_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        win._chart_selected_source = None
        win._chart_selected_severity = None
        win._direct_chart_bar_regions = {}
        win._group_chart_bar_regions = {}
        win._direct_scan_members_by_severity = {label: [] for label in ("Low", "Medium", "High", "Critical")}
        win._group_scan_members_by_severity = {label: [] for label in ("Low", "Medium", "High", "Critical")}
        direct_chart_canvas.bind(
            "<Configure>",
            lambda _event: self._draw_scan_chart(win, getattr(win, "_direct_chart_counts", {}), "direct"),
        )
        group_chart_canvas.bind(
            "<Configure>",
            lambda _event: self._draw_scan_chart(win, getattr(win, "_group_chart_counts", {}), "group"),
        )
        direct_chart_canvas.bind("<Button-1>", lambda event: self._on_scan_chart_click(win, "direct", event))
        group_chart_canvas.bind("<Button-1>", lambda event: self._on_scan_chart_click(win, "group", event))
        self._scan_chart_loading_frame = chart_loading_frame

        stats_detail_var = tk.StringVar(
            value="The scan tree below will populate after the scan completes. Click a direct-member or group-derived bar to focus that branch."
        )
        self._scan_stats_detail_label = ctk.CTkLabel(
            stats_frame,
            textvariable=stats_detail_var,
            text_color="#d0d0d0",
            font=("Segoe UI", 11, "bold"),
        )
        self._scan_stats_detail_label.pack(anchor="w", padx=14, pady=(0, 12))
        win._scan_stats_detail_var = stats_detail_var

        results_frame = ctk.CTkFrame(body_scroll, fg_color="#111111", corner_radius=12)
        results_frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        ctk.CTkLabel(
            results_frame,
            text="Scan Tree",
            text_color="#ffffff",
            font=("Segoe UI", 15, "bold"),
        ).pack(anchor="w", padx=14, pady=(12, 2))

        results_summary_var = tk.StringVar(value="Scanning identities into a tree view...")
        self._scan_results_summary_label = ctk.CTkLabel(
            results_frame,
            textvariable=results_summary_var,
            text_color="#a0a0a0",
            font=("Segoe UI", 11),
            wraplength=1040,
            justify="left",
        )
        self._scan_results_summary_label.pack(anchor="w", padx=14, pady=(0, 10))

        tree_host = tk.Frame(results_frame, bg="#111111", highlightthickness=0)
        tree_host.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self._configure_scan_tree_style(win)

        tree = ttk.Treeview(
            tree_host,
            show="tree",
            selectmode="browse",
            style="Scan.Treeview",
        )
        tree.grid(row=0, column=0, sticky="nsew")

        tree_y = ttk.Scrollbar(tree_host, orient="vertical", command=tree.yview)
        tree_y.grid(row=0, column=1, sticky="ns")
        tree_x = ttk.Scrollbar(tree_host, orient="horizontal", command=tree.xview)
        tree_x.grid(row=1, column=0, sticky="ew")
        tree.configure(yscrollcommand=tree_y.set, xscrollcommand=tree_x.set)

        tree_host.grid_rowconfigure(0, weight=1)
        tree_host.grid_columnconfigure(0, weight=1)

        self._scan_tree = tree
        self._scan_results_frame = tree_host
        win._scan_results_summary_var = results_summary_var
        win._scan_tree_severity_nodes = {}
        self._render_grouped_scan_results(self._scan_tree, [], {}, [], {})
        self._render_scan_severity_members(win, "direct", None)
        self._set_scan_chart_loading(win, True, "Scanning identities...")

        win.protocol("WM_DELETE_WINDOW", partial(self._close_scan_window, win))
        self._animate_window_fade_in(win, duration_ms=220, steps=12)

        return win, scan_status_var

    def _close_scan_window(self, win: Any) -> None:
        """Close the scan window and restore the surrounding UI state."""
        if hasattr(self, "scan_button") and self.scan_button.winfo_exists():
            self.scan_button.configure(state="normal")
        if hasattr(self, "refresh_button") and self.refresh_button.winfo_exists():
            if self._refresh_cooldown:
                self.refresh_button.configure(state="disabled")
            else:
                self.refresh_button.configure(state="normal", text="Refresh Now")
        if self._scan_chart_window is not None and self._scan_chart_window.winfo_exists():
            self._scan_chart_window.destroy()
        self._scan_chart_window = None
        self._scan_chart_button = None
        self._scan_status_label = None
        self._scan_stats_summary_label = None
        self._scan_stats_hint_label = None
        self._scan_stats_detail_label = None
        self._scan_stats_detail_box = None
        self._scan_stats_members_frame = None
        self._scan_chart_loading_frame = None
        self._scan_chart_progress = None
        self._scan_chart_progress_label = None
        self._scan_tree = None
        self._scan_results_summary_label = None
        self._scan_results_frame = None
        self._last_scan_permission_counts = None
        self._last_scan_group_counts = None
        self._last_scan_critical_members = []
        self._last_scan_members_by_severity = {label: [] for label in ("Low", "Medium", "High", "Critical")}
        self._last_scan_group_members_by_severity = {label: [] for label in ("Low", "Medium", "High", "Critical")}
        self._scan_window = None
        if self._auto_refresh_paused_for_scan:
            self._auto_refresh_paused_for_scan = False
            self.start_auto_refresh(self._refresh_interval_ms)
        win.destroy()

    @staticmethod
    def _clear_frame_children(container) -> None:
        """Remove all child widgets from a frame-like container."""
        if container is None or not container.winfo_exists():
            return
        for child in container.winfo_children():
            child.destroy()

    @staticmethod
    def _severity_color(level: str) -> str:
        """Return the UI color used for one risk level."""
        palette = {
            "Low": "#4ec9b0",
            "Medium": "#ffd166",
            "High": "#ff9f1c",
            "Critical": "#ff4d4f",
            "Unknown": "#a0a0a0",
        }
        return palette.get((level or "").strip().title(), "#d0d0d0")

    def _local_permission_risk_level(self, permission_name: str) -> str:
        """Infer a fast local risk level for one permission or role label."""
        local_level = self.scan_service.classify_permission_locally(permission_name)
        if local_level:
            return local_level
        if self.scan_service.is_candidate_risky_permission(permission_name):
            return "Medium"
        return "Low"

    def _add_permission_risk_badge(self, parent: Any, permission_name: str) -> None:
        """Render a colored risk badge for one permission label."""
        risk_level = self._local_permission_risk_level(permission_name)
        ctk.CTkLabel(
            parent,
            text=f"Risk: {risk_level.upper()}",
            text_color="#ffffff",
            fg_color=self._severity_color(risk_level),
            corner_radius=999,
            font=("Segoe UI", 10, "bold"),
            padx=10,
            pady=4,
        ).pack(side="right", padx=(12, 0))

    def _set_scan_chart_loading(self, scan_window: Any, is_loading: bool, message: str = "") -> None:
        """Swap the scan chart area between an indeterminate progress bar and the final graph."""
        if scan_window is None or not scan_window.winfo_exists():
            return

        charts_frame = getattr(scan_window, "_scan_charts_frame", None)
        loading_frame = self._scan_chart_loading_frame
        progress = self._scan_chart_progress
        progress_label = self._scan_chart_progress_label

        if progress_label is not None and progress_label.winfo_exists() and message:
            progress_label.configure(text=message)

        if is_loading:
            if charts_frame is not None and charts_frame.winfo_exists() and charts_frame.winfo_manager():
                charts_frame.pack_forget()
            if loading_frame is not None and loading_frame.winfo_exists() and not loading_frame.winfo_manager():
                loading_frame.pack(fill="x", padx=12, pady=(0, 8))
            if progress is not None and progress.winfo_exists():
                progress.start()
            return

        if loading_frame is not None and loading_frame.winfo_exists() and loading_frame.winfo_manager():
            loading_frame.pack_forget()
        if progress is not None and progress.winfo_exists():
            progress.stop()
        if charts_frame is not None and charts_frame.winfo_exists() and not charts_frame.winfo_manager():
            charts_frame.pack(fill="x", pady=(0, 8))

    @staticmethod
    def _make_scan_tree_branch(
        parent: Any,
        title: str,
        accent_color: str,
        subtitle: str = "",
        expanded: bool = False,
        body_fg: str = "#0b0b0b",
    ) -> Tuple[Any, Any, Dict[str, bool]]:
        """Create a collapsible branch widget for scan results."""
        branch = ctk.CTkFrame(parent, fg_color="#111111", corner_radius=10)
        branch.pack(fill="x", padx=8, pady=6)

        header = ctk.CTkFrame(branch, fg_color="transparent")
        header.pack(fill="x", padx=12, pady=(10, 8))

        text_wrap = 720
        title_label = ctk.CTkLabel(
            header,
            text=title,
            text_color="#ffffff",
            font=("Segoe UI", 12, "bold"),
            justify="left",
            wraplength=text_wrap,
        )
        title_label.pack(side="left", anchor="w")

        if subtitle:
            ctk.CTkLabel(
                header,
                text=subtitle,
                text_color="#a0a0a0",
                font=("Segoe UI", 10),
                justify="left",
            ).pack(side="left", padx=(10, 0))

        chevron_var = tk.StringVar(value="▾" if expanded else "▸")
        toggle_button = ctk.CTkButton(
            header,
            textvariable=chevron_var,
            width=32,
            height=28,
            fg_color=accent_color,
            hover_color=accent_color,
            text_color="#ffffff",
            font=("Segoe UI", 12, "bold"),
            corner_radius=999,
        )
        toggle_button.pack(side="right")

        accent_bar = ctk.CTkFrame(branch, fg_color=accent_color, height=2, corner_radius=999)
        accent_bar.pack(fill="x", padx=12, pady=(0, 6))

        body = ctk.CTkFrame(branch, fg_color=body_fg, corner_radius=8)
        if expanded:
            body.pack(fill="x", padx=12, pady=(0, 12))

        state = {"expanded": expanded}
        toggle_button.configure(command=partial(App._toggle_scan_tree_branch, state, chevron_var, body))
        for clickable in (branch, header, title_label):
            clickable.bind("<Button-1>", partial(App._toggle_scan_tree_branch_click, state, chevron_var, body))

        return branch, body, state

    @staticmethod
    def _toggle_scan_tree_branch(state: Dict[str, bool], chevron_var: tk.StringVar, body: Any) -> None:
        """Expand or collapse a scan tree branch."""
        state["expanded"] = not state["expanded"]
        chevron_var.set("▾" if state["expanded"] else "▸")
        if state["expanded"]:
            body.pack(fill="x", padx=12, pady=(0, 12))
        else:
            body.pack_forget()

    @staticmethod
    def _toggle_scan_tree_branch_click(
        state: Dict[str, bool],
        chevron_var: tk.StringVar,
        body: Any,
        _event: Any,
    ) -> None:
        """Handle a click event for a scan tree branch."""
        App._toggle_scan_tree_branch(state, chevron_var, body)

    @staticmethod
    def _configure_scan_tree_style(window) -> None:
        """Configure the dark treeview styling used in the scan window."""
        style = ttk.Style(window)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Scan.Treeview",
            background="#111111",
            fieldbackground="#111111",
            foreground="#ffffff",
            borderwidth=0,
            rowheight=28,
            relief="flat",
            font=("Segoe UI", 10),
        )
        style.map(
            "Scan.Treeview",
            background=[("selected", "#2a2a2a")],
            foreground=[("selected", "#ffffff")],
        )

    @staticmethod
    def _clear_scan_tree(tree) -> None:
        """Remove all rows from the scan results tree."""
        if tree is None or not tree.winfo_exists():
            return
        tree.delete(*tree.get_children())

    @staticmethod
    def _collapse_scan_tree(tree) -> None:
        """Collapse every branch in the scan results tree before opening a new focus path."""
        if tree is None or not tree.winfo_exists():
            return

        def collapse_node(node_id: str) -> None:
            tree.item(node_id, open=False)
            for child_id in tree.get_children(node_id):
                collapse_node(child_id)

        for root_id in tree.get_children(""):
            collapse_node(root_id)

        current_selection = tree.selection()
        if current_selection:
            tree.selection_remove(*current_selection)

    def _set_scan_results_summary(self, text: str) -> None:
        """Update the grouped-results summary line in the scan window."""
        if self._scan_window is None or not self._scan_window.winfo_exists():
            return
        summary_var = getattr(self._scan_window, "_scan_results_summary_var", None)
        if summary_var is not None:
            summary_var.set(text)
        if self._scan_results_summary_label is not None and self._scan_results_summary_label.winfo_exists():
            self._fit_label_to_parent_width(self._scan_results_summary_label, horizontal_padding=28, min_width=280)

    def _set_scan_status(self, scan_status_var: Optional[tk.StringVar], text: str) -> None:
        if scan_status_var is not None:
            scan_status_var.set(text)
        if self._scan_window is not None and self._scan_window.winfo_exists():
            normalized = (text or "").strip().lower()
            if normalized.startswith("scan complete"):
                self._set_scan_chart_loading(self._scan_window, False)
            else:
                self._set_scan_chart_loading(self._scan_window, True, text)
            if self._scan_stats_summary_label is not None and self._scan_stats_summary_label.winfo_exists():
                self._refresh_scan_stats_header_strip(self._scan_window)
        self._flash_label_text(self._scan_status_label)
        self._set_status(text)

    @staticmethod
    def _preferred_scan_severity(counts: Optional[Dict[str, int]]) -> Optional[str]:
        """Return the highest non-empty severity bucket to focus after a scan finishes."""
        if not counts:
            return None
        for label in ("Critical", "High", "Medium", "Low"):
            if counts.get(label, 0) > 0:
                return label
        return "Low"

    @staticmethod
    def _chart_source_title(chart_key: str) -> str:
        """Return the human label for one statistics chart source."""
        return "Direct Member Permissions" if chart_key == "direct" else "Group-derived Permissions"

    def _draw_all_scan_charts(self, scan_window: Any) -> None:
        """Redraw both inline statistics charts for the active scan window."""
        if scan_window is None or not scan_window.winfo_exists():
            return
        self._draw_scan_chart(scan_window, getattr(scan_window, "_direct_chart_counts", {}), "direct")
        self._draw_scan_chart(scan_window, getattr(scan_window, "_group_chart_counts", {}), "group")

    def _classify_permissions_for_stats(
        self,
        permission_names: List[str],
        parsed_result: Optional[dict] = None,
    ) -> Dict[str, List[str]]:
        """Bucket one permission list by risk severity using scan output first, then local fallback."""
        buckets: Dict[str, List[str]] = {label: [] for label in ("Low", "Medium", "High", "Critical")}
        normalized_names = self.permission_service.dedupe_names(list(permission_names or []))
        severity_by_name: Dict[str, str] = {}

        if parsed_result:
            for severity in ("Critical", "High", "Medium", "Low"):
                for permission in self.permission_service.dedupe_names(list(parsed_result.get(severity.lower()) or [])):
                    key = permission.strip().lower()
                    if key and key not in severity_by_name:
                        severity_by_name[key] = severity

        for permission in normalized_names:
            severity = severity_by_name.get(permission.lower()) or self._local_permission_risk_level(permission)
            buckets.setdefault(severity, []).append(permission)

        return buckets

    def _render_scan_severity_members(self, scan_window: Any, chart_key: str, severity: Optional[str]) -> None:
        """Focus the tree on the selected severity bucket from the chosen statistics chart."""
        detail_var = getattr(scan_window, "_scan_stats_detail_var", None)
        tree = getattr(self, "_scan_tree", None)
        if detail_var is None:
            return

        if chart_key == "group":
            members_by_severity = (
                getattr(scan_window, "_group_scan_members_by_severity", None)
                or self._last_scan_group_members_by_severity
            )
        else:
            members_by_severity = (
                getattr(scan_window, "_direct_scan_members_by_severity", None)
                or self._last_scan_members_by_severity
            )
        member_entries = list(members_by_severity.get(severity or "", []))
        count = len(member_entries)
        scan_window._chart_selected_source = chart_key
        scan_window._chart_selected_severity = severity

        severity_color = self._severity_color(severity or "Unknown")
        source_title = self._chart_source_title(chart_key)
        if self._scan_stats_detail_label is not None and self._scan_stats_detail_label.winfo_exists():
            self._scan_stats_detail_label.configure(text_color=severity_color if severity else "#d0d0d0")

        if not severity:
            detail_var.set("Use either chart to focus the direct-member or group-derived risk branches in the tree.")
        elif count == 0:
            detail_var.set(f"{source_title}: {severity} Risk Members (0) - no identities matched this branch.")
        else:
            detail_var.set(
                f"{source_title}: {severity} Risk Members ({count}) - the matching branch has been expanded in the tree."
            )

        if tree is not None and tree.winfo_exists() and scan_window is not None and scan_window.winfo_exists():
            self._collapse_scan_tree(tree)
            if chart_key == "group":
                group_root = getattr(scan_window, "_scan_tree_group_root", "")
                group_nodes = list(getattr(scan_window, "_scan_tree_group_nodes_by_severity", {}).get(severity or "", []))
                member_nodes = list(getattr(scan_window, "_scan_tree_group_member_nodes_by_severity", {}).get(severity or "", []))
                section_nodes = list(getattr(scan_window, "_scan_tree_group_section_nodes_by_severity", {}).get(severity or "", []))
                if group_root:
                    tree.item(group_root, open=True)
                    tree.selection_set(group_root)
                    tree.focus(group_root)
                    tree.see(group_root)
                for group_node in group_nodes:
                    tree.item(group_node, open=True)
                for member_node in member_nodes:
                    tree.item(member_node, open=True)
                for section_node in section_nodes:
                    tree.item(section_node, open=True)
                if section_nodes:
                    first_target = section_nodes[0]
                elif member_nodes:
                    first_target = member_nodes[0]
                elif group_nodes:
                    first_target = group_nodes[0]
                else:
                    first_target = group_root
                if first_target:
                    tree.selection_set(first_target)
                    tree.focus(first_target)
                    tree.see(first_target)
            else:
                severity_root = getattr(scan_window, "_scan_tree_severity_root", "")
                source_node = getattr(scan_window, "_scan_tree_source_nodes", {}).get(chart_key)
                severity_node = getattr(scan_window, "_scan_tree_severity_nodes", {}).get(chart_key, {}).get(severity or "")
                if severity_root:
                    tree.item(severity_root, open=True)
                if source_node:
                    tree.item(source_node, open=True)
                if severity_node:
                    tree.item(severity_node, open=True)
                    tree.selection_set(severity_node)
                    tree.focus(severity_node)
                    tree.see(severity_node)

        if scan_window is not None and scan_window.winfo_exists():
            self._draw_all_scan_charts(scan_window)

    def _scan_summary_sections(self, parsed_result: dict) -> Tuple[str, List[Tuple[str, List[str]]], str]:
        """Return structured severity sections for one parsed member scan result."""
        overall = self._member_risk_level(parsed_result)
        sections: List[Tuple[str, List[str]]] = []

        for level in ("Critical", "High", "Medium", "Low"):
            permissions = self.permission_service.dedupe_names(list(parsed_result.get(level.lower()) or []))
            if permissions:
                sections.append((level, permissions))

        raw = (parsed_result.get("raw") or "").splitlines()
        fallback_line = raw[0].strip() if raw else ""
        if not sections and not fallback_line:
            fallback_line = "No explicitly classified permissions were found for this member."

        return overall, sections, fallback_line

    def _scan_summary_text(self, parsed_result: dict) -> Tuple[str, str]:
        """Build the compact summary text used in grouped scan result cards."""
        overall, sections, fallback_line = self._scan_summary_sections(parsed_result)
        if sections:
            summary = " | ".join(f"{level}: {', '.join(permissions)}" for level, permissions in sections)
        else:
            summary = fallback_line
        return overall, summary

    def _on_scan_chart_click(self, scan_window: Any, chart_key: str, event: Any) -> None:
        """Open the matching member list when a scan-statistics bar is clicked."""
        if scan_window is None or not scan_window.winfo_exists():
            return
        regions = getattr(scan_window, f"_{chart_key}_chart_bar_regions", {})
        for severity, region in regions.items():
            x1, y1, x2, y2 = region
            if x1 <= event.x <= x2 and y1 <= event.y <= y2:
                self._render_scan_severity_members(scan_window, chart_key, severity)
                break

    @staticmethod
    def _member_risk_level(parsed_result: dict) -> str:
        """Normalize one member scan result into a single display severity."""
        overall = str(parsed_result.get("overall") or "").strip().title()
        if overall in {"Low", "Medium", "High", "Critical"}:
            return overall
        if parsed_result.get("critical"):
            return "Critical"
        if parsed_result.get("high"):
            return "High"
        if parsed_result.get("medium"):
            return "Medium"
        return "Low"

    def _summarize_scan_identity_counts(
        self,
        member_scan_inputs: List[dict],
        member_results: Dict[str, dict],
    ) -> Tuple[
        Dict[str, Dict[str, int]],
        Dict[str, Dict[str, List[Dict[str, Any]]]],
    ]:
        """Count direct-member and group-derived exposures by severity for the statistics charts."""
        counts_by_source: Dict[str, Dict[str, int]] = {
            "direct": {label: 0 for label in ("Low", "Medium", "High", "Critical")},
            "group": {label: 0 for label in ("Low", "Medium", "High", "Critical")},
        }
        members_by_source: Dict[str, Dict[str, List[Dict[str, Any]]]] = {
            "direct": {label: [] for label in ("Low", "Medium", "High", "Critical")},
            "group": {label: [] for label in ("Low", "Medium", "High", "Critical")},
        }
        seen_by_source: Dict[str, Dict[str, Set[str]]] = {
            "direct": {label: set() for label in ("Low", "Medium", "High", "Critical")},
            "group": {label: set() for label in ("Low", "Medium", "High", "Critical")},
        }

        for member_input in member_scan_inputs:
            member_id = str(member_input.get("member_id") or "").strip()
            if not member_id:
                continue

            email = str(member_input.get("email") or member_id)
            groups = list(member_input.get("groups") or [])
            parsed_result = member_results.get(member_id)
            direct_buckets = self._classify_permissions_for_stats(
                list(member_input.get("direct_permissions") or []),
                parsed_result,
            )
            group_buckets = self._classify_permissions_for_stats(
                list(member_input.get("group_permissions") or []),
                parsed_result,
            )

            for chart_key, buckets in (("direct", direct_buckets), ("group", group_buckets)):
                for severity in ("Low", "Medium", "High", "Critical"):
                    permissions = list(buckets.get(severity) or [])
                    if not permissions:
                        continue

                    counts_by_source[chart_key][severity] += 1
                    if member_id in seen_by_source[chart_key][severity]:
                        continue

                    seen_by_source[chart_key][severity].add(member_id)
                    entry = {
                        "email": email,
                        "permissions": permissions,
                    }
                    if chart_key == "group":
                        entry["groups"] = groups
                    members_by_source[chart_key][severity].append(entry)

        for chart_key in members_by_source:
            for severity in members_by_source[chart_key]:
                members_by_source[chart_key][severity].sort(key=lambda item: str(item.get("email") or "").lower())

        return counts_by_source, members_by_source

    def _set_scan_chart_data(
        self,
        counts_by_source: Optional[Dict[str, Dict[str, int]]],
        members_by_source: Optional[Dict[str, Dict[str, List[Dict[str, Any]]]]] = None,
        enable_button: bool = False,
    ) -> None:
        """Store the latest inline scan statistics and update the scan window widgets."""
        direct_counts = dict((counts_by_source or {}).get("direct", {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}))
        group_counts = dict((counts_by_source or {}).get("group", {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}))
        self._last_scan_permission_counts = direct_counts
        self._last_scan_group_counts = group_counts
        self._last_scan_members_by_severity = {
            label: list(((members_by_source or {}).get("direct", {}) or {}).get(label, []))
            for label in ("Low", "Medium", "High", "Critical")
        }
        self._last_scan_group_members_by_severity = {
            label: list(((members_by_source or {}).get("group", {}) or {}).get(label, []))
            for label in ("Low", "Medium", "High", "Critical")
        }
        self._last_scan_critical_members = [
            entry.get("email", "")
            for entry in self._last_scan_members_by_severity.get("Critical", [])
            if entry.get("email")
        ]

        if self._scan_window is None or not self._scan_window.winfo_exists():
            return

        self._scan_window._direct_chart_counts = direct_counts
        self._scan_window._group_chart_counts = group_counts
        self._scan_window._direct_scan_members_by_severity = dict(self._last_scan_members_by_severity)
        self._scan_window._group_scan_members_by_severity = dict(self._last_scan_group_members_by_severity)

        summary_var = getattr(self._scan_window, "_scan_stats_summary_var", None)
        if summary_var is not None:
            if enable_button and counts_by_source is not None:
                direct_total = sum(direct_counts.values())
                group_total = sum(group_counts.values())
                summary_var.set(
                    f"Direct-member exposures: {direct_total}. Group-derived exposures: {group_total}. "
                    f"Click a bar to inspect the matching members."
                )
            else:
                summary_var.set("Scanning identities...")
        if self._scan_stats_summary_label is not None and self._scan_stats_summary_label.winfo_exists() and summary_var is not None:
            self._refresh_scan_stats_header_strip(self._scan_window)

        self._set_scan_chart_loading(self._scan_window, not enable_button, "Scanning identities...")
        self._draw_all_scan_charts(self._scan_window)
        direct_total = sum(direct_counts.values())
        group_total = sum(group_counts.values())
        if not enable_button:
            selected_source = "direct"
            selected_severity = None
        elif direct_total > 0:
            selected_source = "direct"
            selected_severity = self._preferred_scan_severity(direct_counts)
        elif group_total > 0:
            selected_source = "group"
            selected_severity = self._preferred_scan_severity(group_counts)
        else:
            selected_source = "direct"
            selected_severity = None
        self._render_scan_severity_members(self._scan_window, selected_source, selected_severity)

    def _open_scan_chart(self) -> None:
        """Open the current scan's risk-permission bar chart."""
        counts = self._last_scan_permission_counts
        if counts is None:
            messagebox.showinfo("Risk Statistics", "Run a vulnerability scan first.", parent=self)
            return

        if self._scan_chart_window is not None and self._scan_chart_window.winfo_exists():
            self._draw_scan_chart(self._scan_chart_window, counts)
            self._scan_chart_window.lift()
            self._scan_chart_window.focus_force()
            return

        parent = self._scan_window if self._scan_window is not None and self._scan_window.winfo_exists() else self
        win: Any = ctk.CTkToplevel(parent)
        win.title("Risk Statistics")
        win.geometry("760x620")
        win.configure(fg_color="#000000")
        win.transient(parent)
        WindowIconManager.apply(win)
        self._scan_chart_window = win

        header = ctk.CTkFrame(win, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(16, 4))

        ctk.CTkLabel(
            header,
            text="Here are the analysis results of your identities:",
            font=("Segoe UI", 18, "bold"),
            text_color="#ffffff",
        ).pack(side="left")

        ctk.CTkButton(
            header,
            text="Save Chart",
            width=120,
            command=self._save_scan_chart,
            fg_color="#333333",
            hover_color="#444444",
        ).pack(side="right")

        ctk.CTkLabel(
            win,
            text="Values are based on the most recent vulnerability scan and the sum of all "
                 "permissions across unique members.",
            font=("Segoe UI", 11),
            text_color="#a0a0a0",
        ).pack(anchor="w", padx=16, pady=(0, 12))

        chart_body = ctk.CTkFrame(win, fg_color="transparent")
        chart_body.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        canvas = tk.Canvas(win, bg="#111111", highlightthickness=0)
        canvas.pack(in_=chart_body, fill="both", expand=True, pady=(0, 12))
        win._chart_canvas = canvas
        win._chart_counts = dict(counts)
        win._chart_critical_members = list(self._last_scan_critical_members)

        ctk.CTkLabel(
            chart_body,
            text="Critical Members Requiring Attention",
            font=("Segoe UI", 13, "bold"),
            text_color="#ff4d4f",
        ).pack(anchor="w", pady=(0, 6))

        critical_box = ctk.CTkTextbox(
            chart_body,
            height=120,
            fg_color="#111111",
            text_color="#ffb3b3",
            font=("Consolas", 12),
        )
        critical_box.pack(fill="x")
        win._chart_critical_box = critical_box

        win.protocol("WM_DELETE_WINDOW", partial(self._close_scan_chart_window, win))
        canvas.bind("<Configure>", lambda _event: self._draw_scan_chart(win, getattr(win, "_chart_counts", counts)))
        self._animate_window_fade_in(win, duration_ms=220, steps=12)
        self._draw_scan_chart(win, counts)
        self._render_scan_chart_critical_members(win, win._chart_critical_members)

    def _close_scan_chart_window(self, win: Any) -> None:
        """Close the detached scan chart window."""
        self._scan_chart_window = None
        win.destroy()

    @staticmethod
    def _render_scan_chart_critical_members(chart_window: Any, critical_members: List[str]) -> None:
        """Render the last scan's critical-member list into the statistics window."""
        critical_box = getattr(chart_window, "_chart_critical_box", None)
        if critical_box is None or not critical_box.winfo_exists():
            return

        chart_window._chart_critical_members = list(critical_members or [])
        critical_box.configure(state="normal")
        critical_box.delete("1.0", "end")

        if critical_members:
            for member in critical_members:
                critical_box.insert("end", f"[CRITICAL] {member}\n")
        else:
            critical_box.insert("end", "No critical members were detected in the most recent scan.\n")

        critical_box.configure(state="disabled")

    @staticmethod
    def _chart_layout(width: int, height: int) -> Dict[str, Any]:
        """Return the shared chart layout metrics for canvas and exported images."""
        return {
            "left": 70,
            "right": width - 30,
            "top": 30,
            "bottom": height - 70,
            "bar_gap": 24,
            "labels": ("Low", "Medium", "High", "Critical"),
            "colors": {
                "Low": "#4ec9b0",
                "Medium": "#ffd166",
                "High": "#ff9f1c",
                "Critical": "#ff4d4f",
            },
        }

    def _draw_scan_chart(self, chart_window: Any, counts: Dict[str, int], chart_key: str = "direct") -> None:
        """Draw one horizontal severity chart into the requested canvas."""
        chart_canvases = getattr(chart_window, "_chart_canvases", None) or {}
        canvas = chart_canvases.get(chart_key) if chart_canvases else getattr(chart_window, "_chart_canvas", None)
        if canvas is None or not canvas.winfo_exists():
            return

        chart_window.update_idletasks()
        width = max(canvas.winfo_width(), 280)
        height = max(canvas.winfo_height(), 176)
        canvas.delete("all")
        if chart_key == "group":
            chart_window._group_chart_counts = dict(counts)
        else:
            chart_window._direct_chart_counts = dict(counts)

        layout = self._chart_layout(width, height)
        labels = layout["labels"]
        colors = layout["colors"]
        label_gutter = max(96, min(150, int(width * 0.26)))
        right_gutter = max(34, min(70, int(width * 0.1)))
        left = label_gutter
        right = max(left + 80, width - right_gutter)
        top = 18
        bottom = height - 16
        lane_gap = 12
        max_value = max(max(counts.values(), default=0), 1)
        plot_height = max(bottom - top, 80)
        lane_height = max((plot_height - (lane_gap * (len(labels) - 1))) / len(labels), 18)
        selected_source = getattr(chart_window, "_chart_selected_source", None)
        selected_severity = getattr(chart_window, "_chart_selected_severity", None)
        bar_regions: Dict[str, Tuple[float, float, float, float]] = {}

        for index, label in enumerate(labels):
            value = counts.get(label, 0)
            y1 = top + index * (lane_height + lane_gap)
            y2 = y1 + lane_height
            is_selected = selected_source == chart_key and label == selected_severity
            lane_outline = "#ffffff" if is_selected else "#252525"
            lane_width = 2 if is_selected else 1
            canvas.create_rectangle(left, y1, right, y2, fill="#161616", outline=lane_outline, width=lane_width)

            if value > 0:
                fill_width = (right - left) * (value / max_value)
                fill_width = max(fill_width, 14)
                x2 = min(left + fill_width, right)
                canvas.create_rectangle(left, y1, x2, y2, fill=colors[label], outline="")

            mid_y = (y1 + y2) / 2
            canvas.create_text(18, mid_y, text=label, fill=colors[label], anchor="w", font=("Segoe UI", 11, "bold"))
            canvas.create_text(right + 6, mid_y, text=str(value), fill="#ffffff", anchor="w", font=("Segoe UI", 11, "bold"))
            bar_regions[label] = (12, y1 - 4, min(width - 6, right + 36), y2 + 4)

        if chart_key == "group":
            chart_window._group_chart_bar_regions = bar_regions
        else:
            chart_window._direct_chart_bar_regions = bar_regions

    def _save_scan_chart(self) -> None:
        """Save the current chart as an image file for external sharing."""
        chart_window = self._scan_chart_window
        if chart_window is None or not chart_window.winfo_exists():
            messagebox.showinfo("Save Chart", "Open the chart first.", parent=self)
            return

        counts = getattr(chart_window, "_chart_counts", None) or self._last_scan_permission_counts
        critical_members = (
            getattr(chart_window, "_chart_critical_members", None)
            or self._last_scan_critical_members
        )
        if not counts:
            messagebox.showinfo("Save Chart", "No chart data is available yet.", parent=chart_window)
            return

        default_name = f"iam-risk-chart-{time.strftime('%Y%m%d-%H%M%S')}.png"
        path = filedialog.asksaveasfilename(
            parent=chart_window,
            title="Save Risk Chart",
            defaultextension=".png",
            initialfile=default_name,
            filetypes=[
                ("PNG Image", "*.png"),
                ("JPEG Image", "*.jpg"),
                ("PostScript", "*.ps"),
            ],
        )
        if not path:
            return

        try:
            extension = path.rsplit(".", 1)[-1].lower() if "." in path else "png"
            if extension == "ps":
                canvas = getattr(chart_window, "_chart_canvas", None)
                if canvas is None or not canvas.winfo_exists():
                    raise RuntimeError("The chart canvas is not available for export.")
                canvas.postscript(file=path, colormode="color")
            else:
                self._save_scan_chart_image(path, counts, critical_members)
        except Exception as err:
            messagebox.showerror("Save Chart", f"Could not save the chart:\n\n{err}", parent=chart_window)
            return

        messagebox.showinfo("Save Chart", f"Chart saved to:\n{path}", parent=chart_window)

    def _save_scan_chart_image(self, path: str, counts: Dict[str, int], critical_members: Optional[List[str]] = None) -> None:
        """Render the chart to a standalone image file without relying on a screenshot."""
        if Image is None or ImageDraw is None or ImageFont is None:
            raise RuntimeError("Pillow is required to save PNG or JPEG chart images.")
        assert Image is not None and ImageDraw is not None and ImageFont is not None

        width = 1200
        critical_members = list(critical_members or [])
        extra_lines = max(len(critical_members), 1)
        height = 720 + min(extra_lines, 10) * 22
        background = "#0b0b0b"
        plot_background = "#111111"
        axis_color = "#777777"
        grid_color = "#1f1f1f"
        muted_color = "#a0a0a0"
        text_color = "#ffffff"
        image = Image.new("RGB", (width, height), background)
        draw = ImageDraw.Draw(image)
        title_font = ImageFont.load_default()
        body_font = ImageFont.load_default()
        value_font = ImageFont.load_default()

        draw.text((36, 28), "Here are the analysis results of your identities:", fill=text_color, font=title_font)
        draw.text(
            (36, 60),
            "Values are based on the most recent vulnerability scan and the sum of all "
            "permissions across unique members.",
            fill=muted_color,
            font=body_font,
        )

        plot_left = 36
        plot_top = 100
        plot_right = width - 36
        plot_bottom = height - 180
        draw.rounded_rectangle((plot_left, plot_top, plot_right, plot_bottom), radius=18, fill=plot_background)

        layout = self._chart_layout(plot_right - plot_left - 24, plot_bottom - plot_top - 24)
        left = plot_left + 12 + layout["left"]
        right = plot_left + 12 + layout["right"]
        top = plot_top + 12 + layout["top"]
        bottom = plot_top + 12 + layout["bottom"]
        labels = layout["labels"]
        colors = layout["colors"]
        bar_gap = layout["bar_gap"]
        max_value = max(max(counts.values(), default=0), 1)
        chart_width = max(right - left, 240)
        bar_width = (chart_width - (bar_gap * (len(labels) - 1))) / len(labels)

        draw.line((left, top, left, bottom), fill=axis_color, width=2)
        draw.line((left, bottom, right, bottom), fill=axis_color, width=2)

        for step in range(5):
            value = round((max_value / 4) * step)
            y = bottom - ((bottom - top) * (step / 4))
            draw.line((left - 8, y, right, y), fill=grid_color, width=1)
            draw.text((left - 42, y - 8), str(value), fill=muted_color, font=body_font)

        for index, label in enumerate(labels):
            value = counts.get(label, 0)
            x1 = left + index * (bar_width + bar_gap)
            x2 = x1 + bar_width
            bar_height = 0 if value <= 0 else (bottom - top) * (value / max_value)
            y1 = bottom - bar_height
            if value <= 0:
                y1 = bottom - 2
            draw.rectangle((x1, y1, x2, bottom), fill=colors[label])
            draw.text((x1 + 8, y1 - 20), str(value), fill=text_color, font=value_font)
            draw.text((x1 + 8, bottom + 14), label, fill=colors[label], font=body_font)

        section_top = plot_bottom + 26
        draw.text((36, section_top), "Critical Members Requiring Attention", fill="#ff4d4f", font=title_font)
        if critical_members:
            for index, member in enumerate(critical_members[:10]):
                draw.text((36, section_top + 30 + (index * 20)), f"[CRITICAL] {member}", fill="#ffb3b3", font=body_font)
        else:
            draw.text(
                (36, section_top + 30),
                "No critical members were detected in the most recent scan.",
                fill=muted_color,
                font=body_font,
            )

        image.save(path)

    def _confirm_external_scan_use(self) -> bool:
        """Ask for consent before sending IAM permission data to the external risk scanner."""
        if self._external_scan_consent_granted:
            return True

        approved = messagebox.askyesno(
            "External Scan Consent",
            (
                "Vulnerability scans send Cloudflare permission names to an external AI service for risk analysis.\n\n"
                "Group names and member emails are not sent, but permission details are.\n\n"
                "Continue with the external risk scan?"
            ),
            parent=self,
        )
        if approved:
            self._external_scan_consent_granted = True
        return approved

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

    def _render_grouped_scan_results(
        self,
        output,
        group_names: List[str],
        grouped_results: Dict[str, List[dict]],
        errors: List[str],
        members_by_source: Optional[Dict[str, Dict[str, List[Dict[str, Any]]]]] = None,
    ) -> None:
        """Render the scan results into a scalable tree structure."""
        if output is None or not output.winfo_exists():
            return

        tree = output
        self._clear_scan_tree(tree)
        severity_entries_by_source = members_by_source or {
            "direct": getattr(self._scan_window, "_direct_scan_members_by_severity", None) or self._last_scan_members_by_severity,
            "group": getattr(self._scan_window, "_group_scan_members_by_severity", None) or self._last_scan_group_members_by_severity,
        }

        tree.tag_configure("root", foreground="#ffffff")
        tree.tag_configure("muted", foreground="#a0a0a0")
        tree.tag_configure("low", foreground="#4ec9b0")
        tree.tag_configure("medium", foreground="#ffd166")
        tree.tag_configure("high", foreground="#ff9f1c")
        tree.tag_configure("critical", foreground="#ff4d4f")
        tree.tag_configure("unknown", foreground="#a0a0a0")

        if not group_names and not errors:
            tree.insert("", "end", text="No groups or members were found for the selected account.", tags=("muted",))
            return

        severity_root = tree.insert("", "end", text="Risk Classifications", open=True, tags=("root",))
        severity_nodes_by_source: Dict[str, Dict[str, str]] = {}
        source_nodes: Dict[str, str] = {}
        group_entries_by_severity = severity_entries_by_source.get("group", {})

        for chart_key in ("direct",):
            source_title = self._chart_source_title(chart_key)
            source_entries = severity_entries_by_source.get(chart_key, {})
            source_node = tree.insert(
                severity_root,
                "end",
                text=source_title,
                open=(chart_key == "direct"),
                tags=("root",),
            )
            source_nodes[chart_key] = source_node
            severity_nodes_by_source[chart_key] = {}

            for severity in ("Critical", "High", "Medium", "Low"):
                entries = list(source_entries.get(severity, []))
                tag = severity.lower()
                node_id = tree.insert(
                    source_node,
                    "end",
                    text=f"{severity} ({len(entries)})",
                    open=False,
                    tags=(tag,),
                )
                severity_nodes_by_source[chart_key][severity] = node_id

                if not entries:
                    empty_message = (
                        f"No members inherited {severity.lower()}-risk permissions from groups."
                        if chart_key == "group"
                        else f"No members had direct {severity.lower()}-risk permissions."
                    )
                    tree.insert(node_id, "end", text=empty_message, tags=("muted",))
                    continue

                for entry in entries:
                    email = entry.get("email", "(unknown member)")
                    permissions = list(entry.get("permissions") or [])
                    member_node = tree.insert(
                        node_id,
                        "end",
                        text=f"{email} [{severity.upper()}]",
                        open=False,
                        tags=(tag,),
                    )
                    if chart_key == "group":
                        groups = list(entry.get("groups") or [])
                        if groups:
                            tree.insert(
                                member_node,
                                "end",
                                text=f"Groups: {', '.join(groups)}",
                                tags=("muted",),
                            )
                    if permissions:
                        for permission in permissions:
                            tree.insert(member_node, "end", text=permission, tags=("muted",))
                    else:
                        tree.insert(
                            member_node,
                            "end",
                            text="No permissions were explicitly classified in this bucket.",
                            tags=("muted",),
                        )

        group_root = tree.insert("", "end", text="Groups", open=False, tags=("root",))
        group_nodes_by_severity: Dict[str, List[str]] = {label: [] for label in ("Low", "Medium", "High", "Critical")}
        group_member_nodes_by_severity: Dict[str, List[str]] = {label: [] for label in ("Low", "Medium", "High", "Critical")}
        group_section_nodes_by_severity: Dict[str, List[str]] = {label: [] for label in ("Low", "Medium", "High", "Critical")}
        tracked_group_nodes: Dict[str, Set[str]] = {label: set() for label in ("Low", "Medium", "High", "Critical")}
        tracked_group_member_nodes: Dict[str, Set[str]] = {label: set() for label in ("Low", "Medium", "High", "Critical")}
        tracked_group_section_nodes: Dict[str, Set[str]] = {label: set() for label in ("Low", "Medium", "High", "Critical")}
        for group_name in group_names:
            members = sorted(grouped_results.get(group_name, []), key=lambda item: item["email"].lower())
            group_node = tree.insert(
                group_root,
                "end",
                text=f"{group_name} ({len(members)})",
                open=False,
                tags=("low",),
            )

            if not members:
                tree.insert(
                    group_node,
                    "end",
                    text="No members were found in this group during the scan.",
                    tags=("muted",),
                )
                continue

            matching_emails_by_severity: Dict[str, Set[str]] = {label: set() for label in ("Low", "Medium", "High", "Critical")}
            for severity, entries in group_entries_by_severity.items():
                matching_emails = {
                    str(entry.get("email") or "").strip().lower()
                    for entry in entries
                    if group_name in list(entry.get("groups") or [])
                }
                matching_emails_by_severity[severity] = matching_emails
                if matching_emails and group_node not in tracked_group_nodes[severity]:
                    tracked_group_nodes[severity].add(group_node)
                    group_nodes_by_severity[severity].append(group_node)

            for member in members:
                member_email_key = str(member.get("email") or "").strip().lower()
                overall, sections, fallback_line = self._scan_summary_sections(member["risk"])
                member_node = tree.insert(
                    group_node,
                    "end",
                    text=f"{member['email']} [{overall.upper()}]",
                    open=False,
                    tags=((overall or "Unknown").lower(),),
                )

                if sections:
                    for level, permissions in sections:
                        section_node = tree.insert(
                            member_node,
                            "end",
                            text=f"{level} ({len(permissions)})",
                            open=False,
                            tags=(level.lower(),),
                        )
                        if member_email_key in matching_emails_by_severity.get(level, set()):
                            if member_node not in tracked_group_member_nodes[level]:
                                tracked_group_member_nodes[level].add(member_node)
                                group_member_nodes_by_severity[level].append(member_node)
                            if section_node not in tracked_group_section_nodes[level]:
                                tracked_group_section_nodes[level].add(section_node)
                                group_section_nodes_by_severity[level].append(section_node)
                        for permission in permissions:
                            tree.insert(section_node, "end", text=permission, tags=("muted",))
                else:
                    tree.insert(member_node, "end", text=fallback_line, tags=("muted",))

        if errors:
            error_root = tree.insert("", "end", text=f"Warnings ({len(errors)})", open=False, tags=("critical",))
            for err in errors:
                tree.insert(error_root, "end", text=err, tags=("muted",))

        if self._scan_window is not None and self._scan_window.winfo_exists():
            self._scan_window._scan_tree_severity_root = severity_root
            self._scan_window._scan_tree_source_nodes = source_nodes
            self._scan_window._scan_tree_severity_nodes = severity_nodes_by_source
            self._scan_window._scan_tree_group_root = group_root
            self._scan_window._scan_tree_group_nodes_by_severity = group_nodes_by_severity
            self._scan_window._scan_tree_group_member_nodes_by_severity = group_member_nodes_by_severity
            self._scan_window._scan_tree_group_section_nodes_by_severity = group_section_nodes_by_severity

    def _toggle_show(self):
        """Toggle whether the saved token is visually masked in the dashboard."""
        self.token_entry.configure(show="" if self.show_token.get() else "•")

    def _load_selected_token_into_entry(self):
        """Load the selected saved token into the dashboard field without allowing edits."""
        token_type = self.selected_token_name.get()
        token = self.tokens[token_type].get().strip()
        self.token_entry.configure(state="normal")
        self.token_entry.delete(0, "end")
        self.token_entry.insert(0, token)
        self.token_entry.configure(state="disabled")

    def _on_token_type_change(self, choice: str):
        self.selected_token_name.set(choice)
        self._load_selected_token_into_entry()

    def _on_account_choice(self, _choice: str) -> None:
        """Forward account combo-box changes to the account selection handler."""
        self._on_account_selected()

    @staticmethod
    def _mask_account_id(account_id: str) -> str:
        """Return a masked representation of an account id for dashboard display."""
        cleaned = (account_id or "").strip()
        if len(cleaned) <= 4:
            return cleaned
        return f"{'•' * (len(cleaned) - 4)}{cleaned[-4:]}"

    def _format_account_choice_label(self, account_name: str, account_id: str) -> str:
        """Build the account-combo label using the current show/hide preference."""
        visible_id = account_id if self.show_account_id.get() else self._mask_account_id(account_id)
        return f"{account_name}  ({visible_id})"

    def _refresh_account_combo_display(self) -> None:
        """Refresh the account dropdown labels after account data or visibility changes."""
        selected_account_id = self.selected_account_id.get().strip() or self.initial_account_id
        selected_account_name = "Selected"
        values: List[str] = []
        self._account_label_to_id.clear()
        self._account_id_to_label.clear()

        if self.accounts:
            for account in self.accounts:
                account_id = (account.get("id") or "").strip()
                if not account_id:
                    continue
                account_name = (account.get("name") or "(no name)").strip()
                label = self._format_account_choice_label(account_name, account_id)
                values.append(label)
                self._account_label_to_id[label] = account_id
                self._account_id_to_label[account_id] = label
                if account_id == selected_account_id:
                    selected_account_name = account_name

        if not values:
            fallback_label = self._format_account_choice_label(selected_account_name, selected_account_id)
            values = [fallback_label]
            self._account_label_to_id[fallback_label] = selected_account_id
            self._account_id_to_label[selected_account_id] = fallback_label
        elif selected_account_id not in self._account_id_to_label:
            fallback_label = self._format_account_choice_label(selected_account_name, selected_account_id)
            values.insert(0, fallback_label)
            self._account_label_to_id[fallback_label] = selected_account_id
            self._account_id_to_label[selected_account_id] = fallback_label

        self.account_combo.configure(values=values)
        self.account_combo.set(self._account_id_to_label.get(selected_account_id, values[0]))

    def _on_account_selected(self):
        """Update the selected account id when the account dropdown changes."""
        selection = self.account_combo.get().strip()
        account_id = self._account_label_to_id.get(selection, "").strip()
        if len(account_id) == 32:
            self.selected_account_id.set(account_id)
            self._member_permission_summary_cache.clear()
            self._member_permission_fetch_inflight.clear()
            self._all_members = []
            self._all_groups = []
            self._members_loaded_account_id = None
            self._groups_loaded_account_id = None
            self._members_signature = None
            self._groups_signature = None
            self._refresh_account_combo_display()
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
        token_type = self.selected_token_name.get()
        token = self.tokens.get(token_type, tk.StringVar(value="")).get().strip()
        if not token:
            raise ValueError("Please paste a token first, or use 'Manage Tokens'.")
        return CloudflareClient(token)

    # ---------------- Background runner ----------------
    def _run_bg(self, label: str, func: Callable[[], Any]) -> None:
        self._set_status(label + "...")
        self._append(f"\n== {label} ==")
        self._start_daemon_thread(partial(self._run_bg_worker, label, func))

    def _on_success(self, _label: str, result: Any) -> None:
        self._set_status("Ready.")
        if result is not None:
            self._append(str(result))

    def _on_error(self, label: str, err: Exception):
        self._set_status("Ready.")
        self._append(f"[ERROR] {label}: {err}")
        messagebox.showerror("Error", f"{label} failed:\n\n{err}")

    # ---------------- Rendering: CTk "cards" ----------------
    @staticmethod
    def _clear_children(widget: Any) -> None:
        for child in widget.winfo_children():
            child.destroy()

    def _on_member_search_changed(self, *_args) -> None:
        """Debounce member search updates so the UI does less work while typing."""
        if self._member_filter_job is not None:
            try:
                self.after_cancel(self._member_filter_job)
            except tk.TclError:
                pass
        self._member_filter_job = self._after_call(120, self._run_member_filter)

    def _run_member_filter(self) -> None:
        """Run the pending member filter update now."""
        self._member_filter_job = None
        self._apply_member_filter()

    def _clear_member_search(self) -> None:
        """Clear the member search box and restore the full member list."""
        self.member_search_var.set("")

    @staticmethod
    def _member_snapshot_signature(members: List[dict]) -> Tuple[Any, ...]:
        """Build a stable lightweight signature for the current member payload."""
        snapshot: List[Tuple[Any, ...]] = []
        for member in members or []:
            user = member.get("user") or {}
            snapshot.append((
                member.get("id", ""),
                user.get("email", ""),
                member.get("status", ""),
                tuple(sorted(
                    role.get("name", "")
                    for role in (member.get("roles") or [])
                    if isinstance(role, dict) and role.get("name")
                )),
                tuple(sorted(
                    (group.get("id", ""), group.get("name", ""))
                    for group in (member.get("user_groups") or [])
                    if isinstance(group, dict)
                )),
            ))
        return tuple(snapshot)

    @staticmethod
    def _group_snapshot_signature(groups: List[dict]) -> Tuple[Any, ...]:
        """Build a stable lightweight signature for the current group payload."""
        snapshot: List[Tuple[Any, ...]] = []
        for group in groups or []:
            snapshot.append((
                group.get("id", ""),
                group.get("name", ""),
            ))
        return tuple(snapshot)

    def _set_members(self, members: List[dict], account_id: Optional[str] = None, force_render: bool = False) -> None:
        """Store the latest member payload and render the filtered view."""
        signature = self._member_snapshot_signature(members)
        self._all_members = list(members or [])
        self._members_loaded_account_id = account_id or self.selected_account_id.get().strip()
        if not force_render and signature == self._members_signature:
            return
        self._members_signature = signature
        self._apply_member_filter()

    def _set_groups(self, groups: List[dict], account_id: Optional[str] = None, force_render: bool = False) -> None:
        """Store the latest group payload and render the group cards."""
        signature = self._group_snapshot_signature(groups)
        self._all_groups = list(groups or [])
        self._groups_loaded_account_id = account_id or self.selected_account_id.get().strip()
        if not force_render and signature == self._groups_signature:
            return
        self._groups_signature = signature
        self._render_groups_cards(self._all_groups)

    def _load_account_data_parallel(self, account_id: str) -> Tuple[Optional[List[dict]], Optional[List[dict]], Dict[str, Exception]]:
        """Fetch members and groups concurrently to reduce refresh latency."""
        results: Dict[str, Optional[List[dict]]] = {"members": None, "groups": None}
        errors: Dict[str, Exception] = {}

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                "members": executor.submit(self._load_members_for_account, account_id),
                "groups": executor.submit(self._load_groups_for_account, account_id),
            }
            for key, future in futures.items():
                try:
                    results[key] = future.result()
                except Exception as err:
                    errors[key] = err

        return results["members"], results["groups"], errors

    def _load_members_for_account(self, account_id: str) -> List[dict]:
        """Load the member list for one account."""
        return self._client_for("members_read").list_members(account_id).get("result") or []

    def _load_groups_for_account(self, account_id: str) -> List[dict]:
        """Load the user group list for one account."""
        return self._client_for("groups_read").list_user_groups(account_id).get("result") or []

    def _apply_member_filter(self) -> None:
        """Render only the members that match the current search text."""
        filtered_members = self._filter_members(self._all_members, self.member_search_var.get())
        total_members = len(self._all_members)
        shown_members = len(filtered_members)
        previous_results_text = self.member_results_var.get()

        if total_members == 0:
            self.member_results_var.set("No members loaded")
        elif (self.member_search_var.get() or "").strip():
            self.member_results_var.set(f"Showing {shown_members} of {total_members} members")
        else:
            self.member_results_var.set(f"{total_members} members")

        if self.member_results_var.get() != previous_results_text:
            self._flash_label_text(self.member_results_label)

        self._render_members_cards(filtered_members)
        self._scroll_scrollable_frame_to_top(self._dashboard_scroll)

    @staticmethod
    def _scroll_scrollable_frame_to_top(scrollable_frame: Any) -> None:
        """Reset a CTkScrollableFrame-like viewport back to the top when a parent canvas exists."""
        if scrollable_frame is None or not scrollable_frame.winfo_exists():
            return

        scrollable_frame.update_idletasks()
        parent_canvas = getattr(scrollable_frame, "_parent_canvas", None)
        if parent_canvas is not None:
            parent_canvas.yview_moveto(0.0)

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

    @staticmethod
    def _member_search_blob(member: dict) -> str:
        """Build the searchable text blob for one member row."""
        user = member.get("user") or {}
        email = user.get("email", "")
        member_id = member.get("id", "")
        status = member.get("status", "")
        two_factor_value = user.get("two_factor_authentication_enabled", False)
        two_factor_enabled = str(two_factor_value).strip().lower() == "true"
        two_factor_terms = (
            ["2FA Enabled", "Enabled", "Two Factor Enabled", "MFA Enabled"]
            if two_factor_enabled
            else ["2FA Not Enabled", "Not Enabled", "Two Factor Not Enabled", "MFA Not Enabled", "No 2FA"]
        )
        role_names = [role.get("name", "") for role in (member.get("roles") or []) if isinstance(role, dict)]
        group_names = [group.get("name", "") for group in (member.get("user_groups") or []) if isinstance(group, dict)]
        return " ".join([email, member_id, status, *two_factor_terms, *role_names, *group_names]).lower()

    def _member_permissions_summary(self, account_id: str, member: dict) -> str:
        """Return the cached permission summary for the member's first group."""
        group_id = self._member_primary_group_id(member)
        if not group_id:
            return ""

        cache_key = f"{account_id}:{group_id}"
        cached_summary = self._member_permission_summary_cache.get(cache_key)
        if cached_summary is not None:
            return cached_summary

        cached_permissions = self._group_permission_names_cache.get(cache_key)
        if cached_permissions is not None:
            permissions_text = self._build_permission_summary_text(cached_permissions)
            self._member_permission_summary_cache[cache_key] = permissions_text
            return permissions_text

        return ""

    @staticmethod
    def _member_primary_group_id(member: dict) -> str:
        """Return the first user-group id attached to the member card."""
        user_groups = member.get("user_groups") or []
        if not user_groups:
            return ""
        first_group = user_groups[0] if isinstance(user_groups[0], dict) else {}
        return (first_group.get("id") or "").strip()

    @staticmethod
    def _build_permission_summary_text(permission_names: List[str]) -> str:
        """Build a short one-line permission summary for a member card."""
        names = [name for name in (permission_names or []) if name]
        if not names:
            return ""
        permissions_text = ", ".join(names[:5])
        if len(names) > 5:
            permissions_text += f" +{len(names) - 5} more"
        return permissions_text

    def _prefetch_visible_member_permission_summaries(self, account_id: str, members: List[dict]) -> None:
        """Warm missing member-card permission summaries in the background."""
        if not account_id or not members:
            return

        missing_group_ids: List[str] = []
        seen_group_ids = set()
        for member in members[:30]:
            group_id = self._member_primary_group_id(member)
            if not group_id or group_id in seen_group_ids:
                continue
            seen_group_ids.add(group_id)
            cache_key = f"{account_id}:{group_id}"
            if cache_key in self._member_permission_summary_cache or cache_key in self._group_permission_names_cache:
                continue
            if cache_key in self._member_permission_fetch_inflight:
                continue
            missing_group_ids.append(group_id)

        if not missing_group_ids:
            return

        for missing_group_id in missing_group_ids:
            self._member_permission_fetch_inflight.add(f"{account_id}:{missing_group_id}")
        self._start_daemon_thread(
            partial(self._prefetch_visible_member_permission_summaries_worker, account_id, missing_group_ids)
        )

    def _prefetch_visible_member_permission_summaries_worker(
        self,
        account_id: str,
        missing_group_ids: List[str],
    ) -> None:
        """Load missing visible-member permission summaries in the background."""
        updated_any = False

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(self._load_group_permissions_summary, account_id, target_group_id)
                for target_group_id in missing_group_ids
            ]
            for future in futures:
                updated_any = future.result() or updated_any

        if updated_any and self.selected_account_id.get().strip() == account_id:
            self._ui(self._apply_member_filter)

    def _load_group_permissions_summary(self, account_id: str, target_group_id: str) -> bool:
        """Load and cache one group's permission summary."""
        group_cache_key = f"{account_id}:{target_group_id}"
        try:
            cf = self._client_for("groups_read")
            resp = cf.get_user_group(account_id, target_group_id)
            group_detail = resp.get("result") or {}
            permission_names = self.permission_service.extract_group_permission_names(group_detail)
            summary_text = self._build_permission_summary_text(permission_names)
            self._group_permission_names_cache[group_cache_key] = permission_names
            self._member_permission_summary_cache[group_cache_key] = summary_text
            return True
        except (CloudflareAPIError, ConnectionError, Timeout, ValueError):
            self._member_permission_summary_cache.setdefault(group_cache_key, "")
            return False
        finally:
            self._member_permission_fetch_inflight.discard(group_cache_key)

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
            self._populate_member_card(card_widgets, member)

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

            two_factor_label = ctk.CTkLabel(left, text="", text_color="#ff0000", font=("Segoe UI", 11, "bold"))
            two_factor_label.pack(anchor="w")

            status_label = ctk.CTkLabel(left, text="", text_color="#ff9f1c", font=("Segoe UI", 11))
            status_label.pack(anchor="w")


            action_var = tk.StringVar(value="Actions")
            card_widgets: Dict[str, Any] = {
                "card": card,
                "action_var": action_var,
                "member_id": "",
                "email": "",
                "two_factor": "",
                "content_signature": None,
                "pool_index": len(self._member_card_pool),
                "email_label": email_label,
                "status_label": status_label,
                "two_factor_label": two_factor_label,
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
                command=partial(self._on_member_card_action, card_widgets),
            )
            action_combo.pack(side="right")

            _details_host, details_strip = self._create_horizontal_scroll_text(
                card,
                "",
                fg_color="#111111",
                text_color="#a0a0a0",
                font=("Segoe UI", 11),
                height=2,
                padx=(12, 12),
                pady=(0, 10),
            )

            card_widgets["action_combo"] = action_combo
            card_widgets["details_strip"] = details_strip
            self._member_card_pool.append(card_widgets)

        return self._member_card_pool[index]

    def _populate_member_card(self, card_widgets: Dict[str, Any], member: dict) -> None:
        """Update one pooled member card with the latest member data."""
        user = member.get("user") or {}
        email = user.get("email", "(no email)")
        status = member.get("status", "")
        member_id = member.get("id", "")
        two_factor = user.get("two_factor_authentication_enabled", "False")

        roles = member.get("roles") or []
        role_names = [role.get("name", "") for role in roles if isinstance(role, dict)]
        roles_text = ", ".join([role_name for role_name in role_names if role_name]) or "(no roles)"
        new_signature = (email, two_factor, status, member_id, roles_text)
        card_widgets["member_id"] = member_id
        card_widgets["email"] = email
        card_widgets["content_signature"] = new_signature
        card_widgets["email_label"].configure(text=email)
        card_widgets["status_label"].configure(text=status)
        self._set_scroll_text_content(
            card_widgets["details_strip"],
            f"Member ID: {member_id}\nRoles: {roles_text}",
        )
        card_widgets["action_var"].set("Actions")
        card_widgets["two_factor"] = two_factor

        if two_factor is True:
            card_widgets["two_factor_label"].configure(text=f"2FA Enabled", text_color="#22C55E")
        else:
            card_widgets["two_factor_label"].configure(text=f"2FA Not Enabled", text_color="#EF4444")

        card = card_widgets["card"]
        if not card.winfo_manager():
            card.pack(fill="x", padx=6, pady=6)
        card.configure(fg_color="#111111")

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
                self._update_group_card_detail_strip(
                    label_widget,
                    users_text=f"Users: {self._format_members_inline(members)}",
                )
                return
        self._start_daemon_thread(partial(self._load_group_members_worker, account_id, group_id, label_widget))

    def _load_group_members_worker(self, account_id: str, group_id: str, label_widget: ctk.CTkLabel) -> None:
        """Load group members and update one group card label."""
        try:
            cf = self._client_for("groups_read")
            resp = cf.list_user_group_members(account_id, group_id)
            members = resp.get("result") or []
            self._group_members_cache[group_id] = (time.time(), members)
            text = f"Users: {self._format_members_inline(members)}"
            self._ui(self._update_group_card_detail_strip, label_widget, users_text=text)
        except Exception as err:
            self._ui(
                self._update_group_card_detail_strip,
                label_widget,
                users_text=f"Users: (error: {str(err)[:80]})",
            )

    @staticmethod
    def _format_members_inline(members: List[dict], empty_text: str = "(no members)") -> str:
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

        for index, g in enumerate(groups):
            name = g.get("name", "(no name)")
            gid = g.get("id", "")

            card = ctk.CTkFrame(self.groups_list, fg_color="#111111", corner_radius=10)
            card.pack(fill="x", padx=6, pady=6)
            self._animate_card_entry(card, accent_color="#19384f", delay_ms=min(index, 8) * 28)

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

            action_combo.configure(command=partial(self._handle_group_action, group_id=gid, name_label=name_label, card=card))

            ctk.CTkLabel(
                card,
                text=f"Group ID: {gid}",
                text_color="#a0a0a0",
                font=("Segoe UI", 11)
            ).pack(anchor="w", padx=12, pady=(0, 4))

            _details_host, details_strip = self._create_horizontal_scroll_text(
                card,
                "Users: loading...\nPermissions: loading...",
                fg_color="#111111",
                text_color="#a0a0a0",
                font=("Segoe UI", 11),
                height=2,
                padx=(12, 12),
                pady=(0, 10),
            )
            details_strip._group_users_text = "Users: loading..."
            details_strip._group_permissions_text = "Permissions: loading..."

            self._load_group_members_async(gid, details_strip)
            self._load_group_permissions_async(account_id, gid, details_strip)

    def _load_group_permissions_async(self, account_id: str, group_id: str, label_widget: ctk.CTkLabel) -> None:
        """Load one group's permissions in the background for the group card UI."""
        if not account_id or not group_id:
            self._update_group_card_detail_strip(label_widget, permissions_text="Permissions: (unavailable)")
            return
        self._start_daemon_thread(partial(self._load_group_permissions_worker, account_id, group_id, label_widget))

    def _load_group_permissions_worker(
        self,
        account_id: str,
        group_id: str,
        label_widget: ctk.CTkLabel,
    ) -> None:
        """Load one group's permissions and update the matching label."""
        try:
            cf = self._client_for("groups_read")
            resp = cf.get_user_group(account_id, group_id)
            group_detail = resp.get("result") or {}
            permissions_text = self.permission_service.format_group_permissions(group_detail)
            self._ui(
                self._update_group_card_detail_strip,
                label_widget,
                permissions_text=f"Permissions: {permissions_text}",
            )
        except Exception as err:
            self._ui(
                self._update_group_card_detail_strip,
                label_widget,
                permissions_text=f"Permissions: (error: {str(err)[:80]})",
            )

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
        self._run_bg(
            "Edit Member Roles",
            partial(self._edit_member_roles_task, account_id, member_id, final_role_ids, email),
        )
        return final_role_ids

    def _edit_member_roles_task(
        self,
        account_id: str,
        member_id: str,
        final_role_ids: List[str],
        email: str,
    ) -> str:
        """Persist a member's selected role assignments."""
        if not final_role_ids:
            raise ValueError("Select at least one role. Cloudflare does not allow empty role assignments.")
        cf = self._client_for("members_edit")
        cf.update_member_roles(account_id, member_id, final_role_ids)
        fresh = cf.get_member(account_id, member_id)["result"]
        fresh_role_names = [r.get("name") for r in (fresh.get("roles") or [])]
        self._ui(self.refresh_now, True, "Syncing changes")
        return f"Updated {email}\nCloudflare saved: {fresh_role_names}"

    def _remove_member(self, member_id: str, email: str):
        if not messagebox.askyesno("Remove Member", f"Remove {email} from this account?"):
            return
        self._run_bg("Remove Member", partial(self._remove_member_task, member_id, email))

    def _remove_member_task(self, member_id: str, email: str) -> str:
        """Remove one member from the selected account."""
        account_id = self.selected_account_id.get().strip()
        if not account_id:
            raise ValueError("Select an account first.")
        cf = self._client_for("members_edit")
        cf.delete_member(account_id, member_id)
        self._ui(self.refresh_now, True, "Syncing changes")
        return f"Removed member: {email}"

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
        self._start_daemon_thread(partial(self._edit_group_permissions_worker, account_id, group_id))

    def _edit_group_permissions_worker(self, account_id: str, group_id: str) -> None:
        """Load the group policy editor payload and open the permissions window."""
        try:
            payload = self._load_group_permissions_editor_payload(account_id, group_id)
            self._after_call(
                0,
                partial(self._open_group_permissions_window, account_id, group_id, *payload),
            )
        except Exception as err:
            error_text = f"Could not load group permissions:\n\n{err}"
            self._after_call(0, partial(messagebox.showerror, "Error", error_text, parent=self))

    def _load_group_permissions_editor_payload(
        self,
        account_id: str,
        group_id: str,
    ) -> Tuple[dict, str, List[Dict[str, Any]], Optional[str], list, list]:
        """Load the current group policy state and available edit choices."""
        cf = self._client_for("groups_read")
        group = cf.get_user_group(account_id, group_id).get("result") or {}
        policies = group.get("policies") or []
        first = policies[0] if policies else {}
        existing_perm_entries = self.permission_service.extract_policy_entries({"policies": [first]})
        existing_res_ids = [rg.get("id") for rg in (first.get("resource_groups") or []) if rg.get("id")]
        existing_res_id = existing_res_ids[0] if existing_res_ids else None
        access = first.get("access", "allow")
        perm_groups = cf.list_permission_groups(account_id).get("result") or []
        res_groups = cf.list_resource_groups(account_id).get("result") or []
        return group, access, existing_perm_entries, existing_res_id, perm_groups, res_groups

    def _open_group_permissions_window(
        self,
        account_id: str,
        group_id: str,
        group: dict,
        access: str,
        existing_perm_entries: List[Dict[str, Any]],
        existing_res_id: Optional[str],
        perm_groups: list,
        res_groups: list,
    ):
        win = ctk.CTkToplevel(self)
        win.title(f"Permission Policies - {group.get('name', '(group)')}")
        win.geometry("700x620")
        win.transient(self)
        WindowIconManager.apply(win)
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
            fg_color="#ff8c1a", hover_color="#ff9f1c"
        ).pack(side="left", padx=(10, 0))

        ctk.CTkRadioButton(
            access_row, text="Deny", value="deny", variable=access_var,
            fg_color="#ff8c1a", hover_color="#ff9f1c"
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
        perm_options: Dict[str, Dict[str, Any]] = {}

        for entry in existing_perm_entries or []:
            self._add_group_permission_option(
                perm_options,
                field=(entry.get("field") or "permission_groups"),
                item_id=entry.get("id"),
                option_label=entry.get("name") or entry.get("id") or "(unnamed)",
                raw_item=entry.get("raw_item"),
                selected=True,
            )

        for pg in perm_groups or []:
            pid = pg.get("id")
            pname = pg.get("name") or pid or "(unnamed)"
            if not pid:
                continue
            self._add_group_permission_option(
                perm_options,
                field="permission_groups",
                item_id=pid,
                option_label=pname,
                raw_item={"id": pid},
                catalog_known=True,
            )

        preserved_count = sum(1 for option in perm_options.values() if not option.get("catalog_known"))
        if preserved_count:
            ctk.CTkLabel(
                scroll,
                text=(
                "Cloudflare returned existing permissions that are not listed in the "
                "permission catalog. They are preserved here so you can keep or remove them."
                ),
                text_color="#b8b8b8",
                justify="left",
                wraplength=620,
            ).pack(anchor="w", padx=8, pady=(0, 8))

        for option in sorted(perm_options.values(), key=lambda x: (x.get("label") or "").lower()):
            option_id = self._group_permission_option_key(
                option.get("field") or "permission_groups",
                option.get("id"),
                option.get("label") or "",
            )
            option_var = tk.BooleanVar(value=bool(option.get("selected")))
            perm_vars[option_id] = option_var

            row = ctk.CTkFrame(scroll, fg_color="#111111", corner_radius=8)
            row.pack(fill="x", padx=4, pady=4)

            row_content = ctk.CTkFrame(row, fg_color="transparent")
            row_content.pack(fill="x", padx=10, pady=10)

            ctk.CTkCheckBox(
                row_content,
                text=option.get("label") or "(unnamed)",
                variable=option_var,
                onvalue=True,
                offvalue=False,
                text_color="#ffffff",
                fg_color="#ff8c1a",
                hover_color="#ff9f1c",
            ).pack(side="left", anchor="w")

            self._add_permission_risk_badge(row_content, option.get("label") or "(unnamed)")

        btns = ctk.CTkFrame(win, fg_color="#000000")
        btns.pack(fill="x", padx=16, pady=(0, 16))

        ctk.CTkButton(
            btns,
            text="Save",
            command=partial(
                self._save_group_permissions,
                win,
                account_id,
                group_id,
                group,
                access_var,
                rg_choice,
                rg_id_to_label,
                perm_vars,
                perm_options,
            ),
            fg_color="#ff8c1a", hover_color="#ff9f1c", width=120
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btns, text="Cancel", command=win.destroy,
            fg_color="#333333", hover_color="#444444", width=120
        ).pack(side="left")

    @staticmethod
    def _group_permission_option_key(field: str, item_id: Optional[str], option_label: str) -> str:
        """Build a stable key for one group permission option."""
        if item_id:
            return f"id:{item_id.lower()}"
        return f"{field}:{option_label.lower()}"

    def _add_group_permission_option(
        self,
        perm_options: Dict[str, Dict[str, Any]],
        field: str,
        item_id: Optional[str],
        option_label: str,
        raw_item: Any,
        selected: bool = False,
        catalog_known: bool = False,
    ) -> None:
        """Merge one permission option into the edit window option map."""
        cleaned_label = (option_label or item_id or "(unnamed)").strip() or "(unnamed)"
        option_id = self._group_permission_option_key(field, item_id, cleaned_label)
        existing_option = perm_options.get(option_id)
        if existing_option:
            existing_option["selected"] = existing_option["selected"] or selected
            existing_option["catalog_known"] = existing_option["catalog_known"] or catalog_known
            if raw_item is not None and existing_option.get("raw_item") is None:
                existing_option["raw_item"] = raw_item
            if cleaned_label and existing_option.get("label") in {"(unnamed)", existing_option.get("id") or ""}:
                existing_option["label"] = cleaned_label
            return

        perm_options[option_id] = {
            "field": field,
            "id": item_id,
            "label": cleaned_label,
            "raw_item": raw_item,
            "selected": selected,
            "catalog_known": catalog_known,
        }

    def _save_group_permissions(
        self,
        win: Any,
        account_id: str,
        group_id: str,
        group: dict,
        access_var: tk.StringVar,
        rg_choice: tk.StringVar,
        rg_id_to_label: Dict[str, str],
        perm_vars: Dict[str, tk.BooleanVar],
        perm_options: Dict[str, Dict[str, Any]],
    ) -> None:
        """Collect group policy window state and persist the changes."""
        chosen_label = rg_choice.get()
        chosen_rg_id = None
        for rg_id, resource_label in rg_id_to_label.items():
            if resource_label == chosen_label:
                chosen_rg_id = rg_id
                break

        selected_permissions: Dict[str, List[Any]] = {
            "permission_groups": [],
            "permissions": [],
            "roles": [],
        }

        for perm_option_id, perm_var in perm_vars.items():
            if not perm_var.get():
                continue

            option = perm_options.get(perm_option_id) or {}
            field = option.get("field") or "permission_groups"
            item_id = option.get("id")
            raw_item = option.get("raw_item")

            if item_id:
                payload_item: Any = {"id": item_id}
            elif isinstance(raw_item, dict):
                payload_item = dict(raw_item)
            elif raw_item not in (None, ""):
                payload_item = raw_item
            elif option.get("label"):
                payload_item = {"name": option["label"]}
            else:
                continue

            selected_permissions.setdefault(field, []).append(payload_item)

        new_policy = {
            "access": access_var.get(),
            "permission_groups": selected_permissions.get("permission_groups", []),
            "resource_groups": [{"id": chosen_rg_id}] if chosen_rg_id else [],
        }

        for field in ("permissions", "roles"):
            items = selected_permissions.get(field) or []
            if items:
                new_policy[field] = items

        preserved_policies = [
            policy for policy in (group.get("policies") or [])[1:]
            if isinstance(policy, dict)
        ]
        new_policies = [new_policy, *preserved_policies]
        self._start_daemon_thread(
            partial(self._update_group_permissions_worker, win, account_id, group_id, group, new_policies)
        )

    def _update_group_permissions_worker(
        self,
        win: Any,
        account_id: str,
        group_id: str,
        group: dict,
        new_policies: List[dict],
    ) -> None:
        """Persist updated group policies and refresh the UI."""
        try:
            msg = self._update_group_permissions_task(account_id, group_id, group, new_policies)
            self._after_call(0, partial(self._finish_group_permissions_update, win, msg))
        except Exception as err:
            error_text = f"Failed to update permission policies:\n\n{err}"
            self._after_call(0, partial(messagebox.showerror, "Error", error_text, parent=self))

    def _update_group_permissions_task(
        self,
        account_id: str,
        group_id: str,
        group: dict,
        new_policies: List[dict],
    ) -> str:
        """Send the updated group permission policy payload to Cloudflare."""
        cf = self._client_for("groups_edit")
        cf.update_user_group(account_id, group_id, name=group.get("name"), policies=new_policies)
        self._after_call(0, partial(self.refresh_now, True, "Syncing changes"))
        return "Updated group permission policies."

    def _finish_group_permissions_update(self, win: Any, msg: str) -> None:
        """Append a completion message and close the group permissions window."""
        self._append(msg)
        win.destroy()

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

        self._run_bg("Add Member To Group", partial(self._add_member_to_group_task, account_id, group_id, member_id, email))

    def _add_member_to_group_task(self, account_id: str, group_id: str, member_id: str, email: str) -> str:
        """Add one member to a selected group."""
        cf = self._client_for("groups_edit")
        cf.add_members_to_user_group(account_id, group_id, [member_id])
        self._group_members_cache.pop(group_id, None)
        self._ui(self.refresh_now, True, "Syncing changes")
        return f"Added {email} to group {group_id}"

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

        self._run_bg(
            "Remove Member From Group",
            partial(self._remove_member_from_group_task, account_id, group_id, member_id, email),
        )

    def _remove_member_from_group_task(self, account_id: str, group_id: str, member_id: str, email: str) -> str:
        """Remove one member from a selected group."""
        client = self._client_for("groups_edit")
        client.remove_member_from_user_group(account_id, group_id, member_id)
        self._group_members_cache.pop(group_id, None)
        self._ui(self.refresh_now, True, "Syncing changes")
        return f"Removed {email} from group {group_id}"

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
        WindowIconManager.apply(dialog)
        dialog.grab_set()
        dialog.configure(fg_color="#000000")

        ctk.CTkLabel(dialog, text=title, text_color="#ffffff", font=("Segoe UI", 18, "bold")).pack(
            anchor="w", padx=16, pady=(16, 8)
        )

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
            ctk.CTkButton(
                row,
                text=text,
                anchor="w",
                height=54,
                fg_color="#1a1a1a",
                hover_color="#2a2a2a",
                text_color="#ffffff",
                command=partial(self._select_dialog_value, dialog, selected, m),
            ).pack(fill="x", padx=8, pady=8)

        dialog.wait_window()
        return selected["value"]

    # Add Member dialog (email + roles) from main_app.py
    @staticmethod
    def _role_sort_key(role: Dict[str, Any]) -> str:
        """Return a stable lowercase name for role sorting."""
        return str(role.get("name") or "").lower()

    def _add_members_dialog(self, all_roles: List[dict], title: str = "Select Roles") -> Optional[Dict[str, Any]]:
        dialog = ctk.CTkToplevel(self)
        dialog.title(title)
        dialog.geometry("560x520")
        dialog.transient(self)
        WindowIconManager.apply(dialog)
        dialog.grab_set()
        dialog.configure(fg_color="#000000")

        result: Dict[str, Optional[Dict[str, Any]]] = {"value": None}

        ctk.CTkLabel(dialog, text="Member Email", text_color="#ffffff",
                     font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=16, pady=(16, 8))

        email_entry = ctk.CTkEntry(dialog, placeholder_text="user@example.com", width=520)
        email_entry.pack(anchor="w", padx=16, pady=(0, 12))

        ctk.CTkLabel(dialog, text=title, text_color="#ffffff",
                     font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=16, pady=(6, 8))

        scroll = ctk.CTkScrollableFrame(dialog, fg_color="#000000")
        scroll.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        role_vars: Dict[str, tk.BooleanVar] = {}

        for role in sorted(all_roles, key=self._role_sort_key):
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
                fg_color="#ff8c1a",
                hover_color="#ff9f1c",
            ).pack(anchor="w", padx=10, pady=10)

        btns = ctk.CTkFrame(dialog, fg_color="#000000")
        btns.pack(fill="x", padx=16, pady=(0, 16))

        ctk.CTkButton(btns, text="Save", command=partial(self._save_add_member_dialog, dialog, result, email_entry, role_vars),
                      fg_color="#ff8c1a", hover_color="#ff9f1c", width=120).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btns, text="Cancel", command=partial(self._cancel_dialog_result, dialog, result),
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
        WindowIconManager.apply(dialog)
        dialog.grab_set()
        dialog.configure(fg_color="#000000")

        ctk.CTkLabel(dialog, text=title, text_color="#ffffff", font=("Segoe UI", 18, "bold")).pack(
            anchor="w", padx=16, pady=(16, 8)
        )

        selected: Dict[str, Optional[dict]] = {"value": None}

        scroll = ctk.CTkScrollableFrame(dialog, fg_color="#000000")
        scroll.pack(fill="both", expand=True, padx=16, pady=(0, 12))

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
                command=partial(self._select_dialog_value, dialog, selected, m),
            ).pack(fill="x", padx=8, pady=8)

        dialog.wait_window()
        return selected["value"]

    def _pick_roles_dialog(
        self,
        all_roles: List[dict],
        selected_role_ids: Optional[Set[str]] = None,
        title: str = "Select Roles",
    ) -> Optional[List[str]]:
        selected_role_ids = set(selected_role_ids or set())

        dialog = ctk.CTkToplevel(self)
        dialog.title(title)
        dialog.geometry("560x500")
        dialog.transient(self)
        WindowIconManager.apply(dialog)
        dialog.grab_set()
        dialog.configure(fg_color="#000000")

        result: Dict[str, Optional[List[str]]] = {"value": None}

        ctk.CTkLabel(dialog, text=title, text_color="#ffffff",
                     font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=16, pady=(16, 8))

        scroll = ctk.CTkScrollableFrame(dialog, fg_color="#000000")
        scroll.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        role_vars: Dict[str, tk.BooleanVar] = {}

        for role in sorted(all_roles, key=self._role_sort_key):
            role_id = role.get("id", "")
            role_name = role.get("name", "(unnamed role)")
            var = tk.BooleanVar(value=(role_id in selected_role_ids))
            role_vars[role_id] = var

            row = ctk.CTkFrame(scroll, fg_color="#111111", corner_radius=8)
            row.pack(fill="x", padx=4, pady=4)

            row_content = ctk.CTkFrame(row, fg_color="transparent")
            row_content.pack(fill="x", padx=10, pady=10)

            ctk.CTkCheckBox(
                row_content,
                text=role_name,
                variable=var,
                onvalue=True,
                offvalue=False,
                text_color="#ffffff",
                fg_color="#ff8c1a",
                hover_color="#ff9f1c",
            ).pack(side="left", anchor="w")

            self._add_permission_risk_badge(row_content, role_name)

        btns = ctk.CTkFrame(dialog, fg_color="#000000")
        btns.pack(fill="x", padx=16, pady=(0, 16))

        ctk.CTkButton(btns, text="Save", command=partial(self._save_role_selection, dialog, result, role_vars),
                      fg_color="#ff8c1a", hover_color="#ff9f1c", width=120).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btns, text="Cancel", command=partial(self._cancel_dialog_result, dialog, result),
                      fg_color="#333333", hover_color="#444444", width=120).pack(side="left")

        dialog.wait_window()
        return result["value"]

    @staticmethod
    def _select_dialog_value(dialog: Any, result: Dict[str, Any], value: Any) -> None:
        """Store a selected dialog value and close the dialog."""
        result["value"] = value
        dialog.destroy()

    def _save_role_selection(
        self,
        dialog: Any,
        result: Dict[str, Optional[List[str]]],
        role_vars: Dict[str, tk.BooleanVar],
    ) -> None:
        """Save the currently selected role IDs from a dialog."""
        chosen = [selected_role_id for selected_role_id, role_var in role_vars.items() if role_var.get()]
        if not chosen:
            messagebox.showerror("Invalid selection", "Select at least one role.", parent=dialog)
            return
        result["value"] = chosen
        dialog.destroy()

    @staticmethod
    def _cancel_dialog_result(dialog: Any, result: Dict[str, Any]) -> None:
        """Cancel a picker dialog and clear its selected result."""
        result["value"] = None
        dialog.destroy()

    def _save_add_member_dialog(
        self,
        dialog: Any,
        result: Dict[str, Optional[Dict[str, Any]]],
        email_entry: Any,
        role_vars: Dict[str, tk.BooleanVar],
    ) -> None:
        """Save the add-member dialog payload after validating inputs."""
        email = email_entry.get().strip()
        if not email:
            messagebox.showerror("Missing email", "Email is required.", parent=dialog)
            return

        chosen_roles = [role_name for role_name, role_var in role_vars.items() if role_var.get()]
        if not chosen_roles:
            messagebox.showerror("No roles", "Select at least one role.", parent=dialog)
            return

        result["value"] = {"email": email, "roles": chosen_roles}
        dialog.destroy()

    # ---------------- CRUD helpers ----------------
    def _rename_group(self, group_id: str, name_label):
        new_name = simpledialog.askstring("Rename Group", "Enter new group name:", parent=self)
        if not new_name:
            return
        self._run_bg("Rename Group", partial(self._rename_group_task, group_id, name_label, new_name))

    def _rename_group_task(self, group_id: str, name_label: Any, new_name: str) -> str:
        """Rename one group and refresh the UI."""
        account_id = self.selected_account_id.get().strip()
        cf = self._client_for("groups_edit")
        result = cf.update_user_group(account_id, group_id, new_name)["result"]
        final_name = result.get("name", new_name)
        self._ui(name_label.configure, text=final_name)
        self._ui(self.refresh_now, True, "Syncing changes")
        return f"Renamed group to: {final_name}"

    def _delete_group(self, group_id: str, card):
        if not messagebox.askyesno("Delete Group", "Delete this group?"):
            return
        self._run_bg("Delete Group", partial(self._delete_group_task, group_id, card))

    def _delete_group_task(self, group_id: str, card: Any) -> str:
        """Delete one group and remove its card from the UI."""
        account_id = self.selected_account_id.get().strip()
        cf = self._client_for("groups_edit")
        cf.delete_user_group(account_id, group_id)
        self._ui(card.destroy)
        self._ui(self.refresh_now, True, "Syncing changes")
        return f"Deleted group: {group_id}"

    @staticmethod
    def _is_network_error(err: Exception) -> bool:
        return isinstance(err, (ConnectionError, Timeout))

    def _next_backoff_ms(self) -> int:
        return min(self._refresh_interval_ms * (2 ** self._net_failures), self._max_backoff_ms)

    # ---------------- Actions ----------------
    def on_verify(self):
        self._run_bg("Verify Token", self._verify_selected_account_token)

    def on_list_accounts(self):
        self._run_bg("List Accounts", self._list_accounts_task)

    def _verify_selected_account_token(self) -> str:
        """Verify the selected account token and return a summary string."""
        account_id = self.selected_account_id.get().strip()
        if not account_id:
            raise ValueError("No account selected.")
        cf = self._client_for("verify")
        data = cf.verify_token_for_account(account_id)
        result = data.get("result") or {}
        return (
            f"Token status: {result.get('status', 'unknown')}\n"
            f"Token id: {result.get('id', '')}\n"
            f"Not before: {result.get('not_before', '')}\n"
            f"Expires on: {result.get('expires_on', '')}"
        )

    def _list_accounts_task(self) -> str:
        """Load available accounts and select the first one in the UI."""
        cf = self._client_for("accounts")
        data = cf.list_accounts()
        self.accounts = data.get("result") or []
        if not self.accounts:
            return "No accounts returned."

        first_id = self.accounts[0].get("id", "")
        self._ui(self._apply_list_accounts_result, first_id)
        return f"Loaded {len(self.accounts)} accounts."

    def _apply_list_accounts_result(self, first_id: str) -> None:
        """Apply a freshly loaded account list to the account picker."""
        self.selected_account_id.set(first_id)
        self._refresh_account_combo_display()
        self._append(f"Selected account_id = {first_id}")

    def scan_all_members(self):
        """Scan all members, batch uncached risk profiles, and render grouped results."""
        existing_scan_window = getattr(self, "_scan_window", None)
        if existing_scan_window is not None and existing_scan_window.winfo_exists():
            existing_scan_window.lift()
            existing_scan_window.focus_force()
            return

        if not self._confirm_external_scan_use():
            self._set_status("External scan cancelled.")
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

        _win, scan_status_var = self.open_scan_window()
        self._start_daemon_thread(
            partial(self._scan_all_members_worker, account_id, members, groups, scan_status_var)
        )

    def _scan_all_members_worker(
        self,
        account_id: str,
        members: List[dict],
        groups: List[dict],
        scan_status_var: tk.StringVar,
    ) -> None:
        """Run the full risk scan workflow in the background."""
        self._ui(self._set_scan_status, scan_status_var, "Loading members and groups...")
        group_names, grouped_results = self._initialize_scan_group_results(groups)
        errors: List[str] = []

        self._ui(self._set_scan_status, scan_status_var, "Loading group permissions...")
        group_permissions_by_id, permission_errors = self.permission_service.build_group_permissions_cache(
            account_id,
            members,
            self._client_for,
            cached_permissions_by_id=self._cached_group_permissions_for_account(account_id),
        )
        self._cache_group_permission_names(account_id, group_permissions_by_id)
        errors.extend(permission_errors)

        member_scan_inputs, parsed_risk_cache, scan_requests, local_prefill_by_cache_key, cached_hits, local_hits = (
            self._prepare_member_scan_inputs(account_id, members, group_permissions_by_id, errors)
        )

        self._ui(
            self._set_scan_results_summary,
            (
                f"Loaded {len(members)} members, {len(group_permissions_by_id)} groups, "
                f"{cached_hits} cached profiles, {local_hits} locally resolved profiles, "
                f"and {len(scan_requests)} unresolved model evaluations."
            ),
        )
        self._ui(
            self._set_scan_status,
            scan_status_var,
            f"Scanning {len(scan_requests)} unresolved risk profiles..."
        )

        self._run_batched_member_scan(
            scan_requests,
            local_prefill_by_cache_key,
            parsed_risk_cache,
            errors,
            scan_status_var,
        )

        member_results_by_id, member_email_by_id = self._collect_member_scan_results(
            member_scan_inputs,
            parsed_risk_cache,
            group_names,
            grouped_results,
        )
        self._finalize_member_scan(
            member_scan_inputs,
            member_results_by_id,
            member_email_by_id,
            group_names,
            grouped_results,
            errors,
            scan_status_var,
        )

    @staticmethod
    def _initialize_scan_group_results(groups: List[dict]) -> Tuple[List[str], Dict[str, List[dict]]]:
        """Prepare empty grouped scan buckets for each discovered group."""
        group_names: List[str] = []
        grouped_results: Dict[str, List[dict]] = {}
        for group in groups:
            if not isinstance(group, dict):
                continue
            group_name = (group.get("name") or "").strip()
            if not group_name or group_name in grouped_results:
                continue
            group_names.append(group_name)
            grouped_results[group_name] = []
        return group_names, grouped_results

    def _cache_group_permission_names(self, account_id: str, group_permissions_by_id: Dict[str, List[str]]) -> None:
        """Persist loaded group permission names into the member-card cache."""
        for group_id, permission_names in group_permissions_by_id.items():
            self._group_permission_names_cache[f"{account_id}:{group_id}"] = list(permission_names)

    def _prepare_member_scan_inputs(
        self,
        account_id: str,
        members: List[dict],
        group_permissions_by_id: Dict[str, List[str]],
        errors: List[str],
    ) -> Tuple[List[dict], Dict[str, dict], Dict[str, dict], Dict[str, dict], int, int]:
        """Build scan requests and local/cache hits for the current member batch."""
        member_scan_inputs: List[dict] = []
        parsed_risk_cache: Dict[str, dict] = {}
        scan_requests: Dict[str, dict] = {}
        local_prefill_by_cache_key: Dict[str, dict] = {}
        cached_hits = 0
        local_fast_path_hits = 0

        for member in members:
            try:
                member_input, cached_result, scan_request, local_prefill, was_cached, was_local = (
                    self._prepare_single_member_scan(
                        account_id,
                        member,
                        group_permissions_by_id,
                        scan_requests,
                    )
                )
                member_scan_inputs.append(member_input)
                if cached_result is not None:
                    parsed_risk_cache[member_input["cache_key"]] = cached_result
                if local_prefill is not None:
                    local_prefill_by_cache_key[member_input["cache_key"]] = local_prefill
                if scan_request is not None:
                    scan_requests[member_input["cache_key"]] = scan_request
                if was_cached:
                    cached_hits += 1
                if was_local:
                    local_fast_path_hits += 1
            except Exception as err:
                errors.append(str(err))

        return (
            member_scan_inputs,
            parsed_risk_cache,
            scan_requests,
            local_prefill_by_cache_key,
            cached_hits,
            local_fast_path_hits,
        )

    def _prepare_single_member_scan(
        self,
        account_id: str,
        member: dict,
        group_permissions_by_id: Dict[str, List[str]],
        existing_scan_requests: Dict[str, dict],
    ) -> Tuple[dict, Optional[dict], Optional[dict], Optional[dict], bool, bool]:
        """Prepare one member's scan metadata and any needed model request."""
        user = member.get("user") or {}
        email = user.get("email", "(no email)")
        member_id = (member.get("id") or "").strip() or email
        direct_permissions = self.permission_service.dedupe_names(
            [role.get("name", "") for role in (member.get("roles") or []) if isinstance(role, dict)]
        )
        group_permissions: List[str] = []
        for group in member.get("user_groups") or []:
            if not isinstance(group, dict):
                continue
            group_id = (group.get("id") or "").strip()
            if not group_id:
                continue
            group_permissions.extend(group_permissions_by_id.get(group_id, []))
        group_permissions = self.permission_service.dedupe_names(group_permissions)
        roles_text = ", ".join(self.permission_service.dedupe_names(direct_permissions + group_permissions)) or "(no roles)"
        member_group_names = self._member_group_names(member)
        group_name = ", ".join(member_group_names) or "Other"
        cache_key = self.scan_service.scan_profile_key(group_name, roles_text)
        member_input = {
            "email": email,
            "member_id": member_id,
            "groups": member_group_names or ["Other"],
            "direct_permissions": direct_permissions,
            "group_permissions": group_permissions,
            "cache_key": cache_key,
        }

        cached_result = self._risk_scan_cache.get(cache_key)
        if cached_result and not self.scan_service.is_rate_limited(cached_result.get("raw")):
            return member_input, cached_result, None, None, True, False

        if cache_key in existing_scan_requests:
            return member_input, None, None, None, False, False

        self._risk_scan_cache.pop(cache_key, None)
        local_scan = self.scan_service.prepare_local_scan(roles_text)
        local_prefill = local_scan["prefill"]
        if local_scan["resolved_locally"]:
            self._risk_scan_cache[cache_key] = local_prefill
            return member_input, local_prefill, None, local_prefill, False, True

        scan_request = {
            "email": email,
            "member_id": member_id,
            "group_name": group_name,
            "roles_text": roles_text,
            "candidate_permissions": list(local_scan["unresolved_permissions"]),
        }
        return member_input, None, scan_request, local_prefill, False, False

    def _run_batched_member_scan(
        self,
        scan_requests: Dict[str, dict],
        local_prefill_by_cache_key: Dict[str, dict],
        parsed_risk_cache: Dict[str, dict],
        errors: List[str],
        scan_status_var: tk.StringVar,
    ) -> None:
        """Resolve any remaining member risk scans through the batch scanner."""
        if not scan_requests:
            return

        try:
            batch_results = self.scan_service.scan_member_risks_batch(
                scan_requests,
                status_callback=partial(self._update_scan_status_text, scan_status_var),
            )
            for cache_key, parsed_result in batch_results.items():
                merged_result = self.scan_service.merge_scan_results(
                    local_prefill_by_cache_key.get(cache_key, self.scan_service.default_scan_result()),
                    parsed_result,
                )
                parsed_risk_cache[cache_key] = merged_result
                self._risk_scan_cache[cache_key] = merged_result
        except Exception as err:
            errors.append(f"Batched risk scan failed: {err}")

    def _update_scan_status_text(self, scan_status_var: tk.StringVar, text: str) -> None:
        """Push a status update from the batch scanner onto the UI thread."""
        self._ui(self._set_scan_status, scan_status_var, text)

    def _collect_member_scan_results(
        self,
        member_scan_inputs: List[dict],
        parsed_risk_cache: Dict[str, dict],
        group_names: List[str],
        grouped_results: Dict[str, List[dict]],
    ) -> Tuple[Dict[str, dict], Dict[str, str]]:
        """Assemble per-member and per-group scan results for rendering."""
        member_results_by_id: Dict[str, dict] = {}
        member_email_by_id: Dict[str, str] = {}

        for member_input in member_scan_inputs:
            parsed_result = parsed_risk_cache.get(member_input["cache_key"])
            if parsed_result is None:
                continue

            member_results_by_id[member_input["member_id"]] = parsed_result
            member_email_by_id[member_input["member_id"]] = member_input["email"]

            for target_group in member_input["groups"]:
                if target_group not in grouped_results:
                    group_names.append(target_group)
                    grouped_results[target_group] = []
                grouped_results[target_group].append(
                    {"email": member_input["email"], "risk": parsed_result}
                )

        return member_results_by_id, member_email_by_id

    def _finalize_member_scan(
        self,
        member_scan_inputs: List[dict],
        member_results_by_id: Dict[str, dict],
        member_email_by_id: Dict[str, str],
        group_names: List[str],
        grouped_results: Dict[str, List[dict]],
        errors: List[str],
        scan_status_var: tk.StringVar,
    ) -> None:
        """Render the finished scan results and update the scan window."""
        counts_by_source, members_by_source = self._summarize_scan_identity_counts(
            member_scan_inputs,
            member_results_by_id,
        )
        scan_summary = (
            f"Showing {len(member_results_by_id)} scanned identities across {len(group_names)} groups."
        )
        if errors:
            scan_summary += f" {len(errors)} warnings were captured during the scan."
        self._ui(self._set_scan_results_summary, scan_summary)
        self._ui(
            self._set_scan_chart_data,
            counts_by_source,
            members_by_source,
            bool(member_results_by_id),
        )
        self._ui(
            self._render_grouped_scan_results,
            self._scan_tree,
            group_names,
            grouped_results,
            errors,
            members_by_source,
        )
        self._ui(self._set_scan_status, scan_status_var, "Scan complete.")

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
        self._run_bg("Add Member", partial(self._add_member_task, email, role_input))

    def _add_member_task(self, email: str, role_input: List[str]) -> str:
        """Create a new member after resolving the chosen role names to ids."""
        account_id = self.selected_account_id.get().strip()
        if not account_id:
            raise ValueError("Select an account first.")

        cf = self._client_for("members_edit")
        self._ensure_role_lookup_loaded(cf, account_id)
        role_ids = self._resolve_role_inputs(role_input)
        result = cf.add_member(account_id, email, role_ids)
        self._ui(self.refresh_now, True, "Syncing changes")
        return f"Added member: {email}\nResponse: {result.get('result')}"

    def _ensure_role_lookup_loaded(self, cf: CloudflareClient, account_id: str) -> None:
        """Load the role lookup tables if they are not already populated."""
        if self.role_name_to_id:
            return
        data = cf.list_roles(account_id)
        self.roles = data.get("result") or []
        self.role_name_to_id = {role["name"]: role["id"] for role in self.roles if role.get("name") and role.get("id")}
        self.role_id_to_name = {role["id"]: role["name"] for role in self.roles if role.get("name") and role.get("id")}

    def _resolve_role_inputs(self, role_input: List[str]) -> List[str]:
        """Resolve role labels or ids from a picker dialog into role ids."""
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
        return role_ids

    def create_group(self):
        group_name = simpledialog.askstring("Create Group", "Enter group name:", parent=self)
        if not group_name:
            return

        self._run_bg("Create Group", partial(self._create_group_task, group_name))

    def _create_group_task(self, group_name: str) -> str:
        """Create a group for the selected account and refresh the dashboard."""
        account_id = self.selected_account_id.get().strip()
        if not account_id:
            raise ValueError("Select an account first.")
        cf = self._client_for("groups_edit")
        result = cf.create_user_group(account_id, group_name)["result"]
        self._group_members_cache.clear()
        self._ui(self.refresh_now, True, "Syncing changes")
        return f"Created group: {result.get('name', group_name)}"

    def on_list_roles(self):
        self._run_bg("List Roles", self._list_roles_task)

    def _list_roles_task(self) -> str:
        """Load roles for the selected account and return a printable summary."""
        account_id = self.selected_account_id.get().strip()
        if not account_id:
            raise ValueError("Select an account first.")
        cf = self._get_client()
        data = cf.list_roles(account_id)
        self.roles = data["result"]
        self.role_name_to_id = {role["name"]: role["id"] for role in self.roles if role.get("name") and role.get("id")}
        self.role_id_to_name = {role["id"]: role["name"] for role in self.roles if role.get("name") and role.get("id")}
        out = ["Roles:"]
        for role in self.roles:
            out.append(f"- {role['name']} | id={role['id']}")
        return "\n".join(out)

    def refresh_now(self, force: bool = False, reason: str = "Refresh Now"):
        """Refresh account data immediately, with optional bypass for change-driven syncs."""
        existing_scan_window = getattr(self, "_scan_window", None)
        if existing_scan_window is not None and existing_scan_window.winfo_exists():
            existing_scan_window.lift()
            existing_scan_window.focus_force()
            return

        if self._refresh_inflight:
            return

        if self._refresh_cooldown and not force:
            return

        if not force:
            self._refresh_cooldown = True
        if hasattr(self, "refresh_button") and not force:
            self.refresh_button.configure(state="disabled", text="Refresh Now (5s)")
            for i in range(1, 5):
                self._after_call(
                    i * 1000,
                    partial(self._update_refresh_button_countdown, 5 - i),
                )

        if not force:
            self._after_call(5000, self._reenable_refresh_button)

        self._refresh_inflight = True
        self._run_bg(reason, partial(self._refresh_now_task, force))

    def _update_refresh_button_countdown(self, remaining_seconds: int) -> None:
        """Refresh the manual refresh button countdown label when it still exists."""
        if self.refresh_button.winfo_exists():
            self.refresh_button.configure(text=f"Refresh Now ({remaining_seconds}s)")

    def _refresh_now_task(self, force: bool) -> str:
        """Fetch the latest members/groups immediately and refresh the UI."""
        try:
            account_id = self.selected_account_id.get().strip()
            if not account_id:
                raise ValueError("Select an account first.")

            members, groups, errors = self._load_account_data_parallel(account_id)
            if errors:
                raise next(iter(errors.values()))

            members = members or []
            groups = groups or []

            self._ui(self._set_members, members, account_id, force)
            self._ui(self._set_groups, groups, account_id, force)
            self._ui(self._set_status, "Auto-refreshed.")
            self._ui(self._append, f"Refreshed: {len(members)} members, {len(groups)} groups.")
            return f"Refreshed: {len(members)} members, {len(groups)} groups."
        finally:
            self._refresh_inflight = False

    # ---------------- Auto-refresh ----------------
    def start_auto_refresh(self, interval_ms: int = 10_000) -> None:
        self._refresh_interval_ms = interval_ms
        self._schedule_refresh()

    def stop_auto_refresh(self):
        if self._refresh_job is not None:
            try:
                self.after_cancel(self._refresh_job)
            except tk.TclError:
                pass
            self._refresh_job = None

    def _schedule_refresh(self, delay_ms: Optional[int] = None) -> None:
        if delay_ms is None:
            delay_ms = self._refresh_interval_ms
        self._refresh_job = self._after_call(delay_ms, self._refresh_tick)

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
        except ValueError:
            self._schedule_refresh(self._refresh_interval_ms)
            return

        self._refresh_inflight = True
        threading.Thread(target=self._refresh_bg, daemon=True).start()

    def _refresh_bg(self):
        account_id = self.selected_account_id.get().strip()
        network_failed = False

        try:
            members, groups, errors = self._load_account_data_parallel(account_id)

            if members is not None:
                self._ui(self._set_members, members, account_id, False)
            if groups is not None:
                self._ui(self._set_groups, groups, account_id, False)

            for key, err in errors.items():
                if self._is_network_error(err):
                    network_failed = True
                self._ui(self._append, f"[AUTO-REFRESH ERROR][{key}] {repr(err)}")

        finally:
            self._ui(self._finalize_refresh_bg, network_failed)

    def _finalize_refresh_bg(self, network_failed: bool) -> None:
        """Reset refresh state and schedule the next auto-refresh tick."""
        self._refresh_inflight = False
        if network_failed:
            self._net_failures += 1
            wait = self._next_backoff_ms()
            self._set_status(f"Network issue — retrying in {wait // 1000}s")
            self._schedule_refresh(wait)
            return

        self._net_failures = 0
        self._set_status("Auto-refreshed.")
        self._schedule_refresh(self._refresh_interval_ms)

    # ---------------- Token Manager ----------------
    def open_token_manager(self):
        TokenManagerWindow(self, on_saved=self._on_tokens_saved)

    def _on_tokens_saved(self, _tokens: Any) -> None:
        """Reload token data after the token-manager window saves changes."""
        self.saved_tokens = self.store.load()
        for key in self.tokens:
            self.tokens[key].set(self.saved_tokens.get(key, ""))
        self._load_selected_token_into_entry()
        self._append("Tokens reloaded from disk.")

    def clear_local_data(self) -> None:
        """Remove persistent local data and reset the current session state."""
        confirmed = messagebox.askyesno(
            "Clear Local Data",
            "This will remove saved encrypted tokens, delete the runtime log, close open scan windows, "
            "and clear cached member, group, and scan data from this device.\n\nContinue?",
            parent=self,
        )
        if not confirmed:
            return

        warnings: List[str] = []
        cleared_items: List[str] = []

        try:
            self.store.clear()
            cleared_items.append("saved encrypted tokens")
        except Exception as err:
            warnings.append(f"Tokens could not be fully cleared: {err}")

        try:
            clear_runtime_log()
            cleared_items.append("runtime log")
        except Exception as err:
            warnings.append(f"Runtime log could not be deleted: {err}")

        self._reset_local_session_state()
        cleared_items.append("cached member, group, and scan data")

        append_runtime_log("App.clear_local_data", f"Cleared local data: {', '.join(cleared_items)}.")
        self._append(f"Cleared local data: {', '.join(cleared_items)}.")
        self._set_status("Local data cleared from this device.")

        message = (
            "Local app data was cleared from this device.\n\n"
            f"Removed: {', '.join(cleared_items)}."
        )
        if warnings:
            message += "\n\nWarnings:\n- " + "\n- ".join(warnings)
        messagebox.showinfo("Local Data Cleared", message, parent=self)

    def _reset_local_session_state(self) -> None:
        """Clear in-memory sensitive state so the visible dashboard matches local cleanup."""
        self.saved_tokens = {token_type: "" for token_type in self.store.TOKEN_TYPES}
        for token_var in self.tokens.values():
            token_var.set("")
        self._load_selected_token_into_entry()

        self._group_members_cache.clear()
        self.roles = []
        self.role_name_to_id.clear()
        self.role_id_to_name.clear()
        self._risk_scan_cache.clear()
        self._group_permission_names_cache.clear()
        self._member_permission_summary_cache.clear()
        self._member_permission_fetch_inflight.clear()
        self._all_members = []
        self._all_groups = []
        self._members_loaded_account_id = None
        self._groups_loaded_account_id = None
        self._external_scan_consent_granted = False
        self._members_signature = None
        self._groups_signature = None
        self.member_search_var.set("")
        self.member_results_var.set("No members loaded")

        self._last_scan_permission_counts = None
        self._last_scan_group_counts = None
        self._last_scan_critical_members = []
        self._last_scan_members_by_severity = {label: [] for label in ("Low", "Medium", "High", "Critical")}
        self._last_scan_group_members_by_severity = {label: [] for label in ("Low", "Medium", "High", "Critical")}

        if self._scan_chart_window is not None and self._scan_chart_window.winfo_exists():
            self._scan_chart_window.destroy()
        self._scan_chart_window = None

        if self._scan_window is not None and self._scan_window.winfo_exists():
            self._scan_window.destroy()
        self._scan_window = None

        self._render_members_cards([])
        self._render_groups_cards([])
        if self.output is not None and self.output.winfo_exists():
            self.output.delete("1.0", "end")

    def _on_close(self):
        append_runtime_log("App._on_close", "Main app window is closing.")
        if self._data_notice_window is not None and self._data_notice_window.winfo_exists():
            self._data_notice_window.destroy()
            self._data_notice_window = None
        self.stop_auto_refresh()
        self.destroy()
