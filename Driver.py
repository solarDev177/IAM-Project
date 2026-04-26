# Cloudflare IAM Explorer
# Driver file

import customtkinter as ctk
import threading
import time
import traceback
from pathlib import Path
from tkinter import messagebox

from login import LoginWindow
from runtime_log import append_runtime_log
from startup_window import StartupWindow


RUNTIME_ERROR_LOG = Path.home() / "CloudflareIAMExplorer-runtime.log"


def _append_runtime_log(header: str, details: str) -> None:
    """Append one runtime error block to a user-accessible log file."""
    append_runtime_log(header, details)


def _report_runtime_error(root, header: str, details: str) -> None:
    """Persist and display a runtime error that would otherwise vanish in packaged builds."""
    _append_runtime_log(header, details)
    try:
        messagebox.showerror(
            "Cloudflare IAM Explorer Error",
            f"{header}\n\n{details}\n\nA runtime log was written to:\n{RUNTIME_ERROR_LOG}",
        )
    except Exception:
        pass
    try:
        if root is not None and root.winfo_exists():
            root.destroy()
    except Exception:
        pass


def main():
    root = ctk.CTk()
    root.withdraw()
    root._visible_window_grace_until = time.monotonic() + 10.0
    root._shutdown_requested = False
    append_runtime_log("Driver.main", "Hidden root created and startup flow beginning.")

    def on_tk_callback_exception(exc_type, exc_value, exc_traceback):
        details = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        _report_runtime_error(root, "Unhandled Tk callback exception", details)

    def on_thread_exception(args):
        details = "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback))
        _report_runtime_error(root, f"Unhandled background thread exception: {args.thread.name}", details)

    root.report_callback_exception = on_tk_callback_exception
    threading.excepthook = on_thread_exception

    def schedule_visible_window_grace(seconds: float = 5.0):
        if root.winfo_exists():
            root._visible_window_grace_until = time.monotonic() + max(1.0, seconds)

    def open_login():
        if root.winfo_exists():
            schedule_visible_window_grace(8.0)
            append_runtime_log("Driver.open_login", "Creating login window.")
            login_window = LoginWindow(master=root)
            root._login_window = login_window
            try:
                login_window.deiconify()
                login_window.lift()
                login_window.focus_force()
                login_window.attributes("-topmost", True)
                login_window.after(180, lambda: login_window.winfo_exists() and login_window.attributes("-topmost", False))
            except Exception:
                pass

    def monitor_visible_windows():
        if not root.winfo_exists():
            return
        if getattr(root, "_shutdown_requested", False):
            return

        visible_children = []
        for child in root.winfo_children():
            try:
                if child.winfo_exists() and (child.winfo_viewable() or child.winfo_ismapped()):
                    visible_children.append(child)
            except Exception:
                continue

        if not visible_children and time.monotonic() > getattr(root, "_visible_window_grace_until", 0.0):
            child_states = []
            for child in root.winfo_children():
                try:
                    child_states.append(
                        f"{child.__class__.__name__}: state={child.state()} "
                        f"exists={child.winfo_exists()} "
                        f"mapped={child.winfo_ismapped()} "
                        f"viewable={child.winfo_viewable()}"
                    )
                except Exception:
                    child_states.append(f"{child.__class__.__name__}: state-unavailable")
            _report_runtime_error(
                root,
                "No visible application window remained open",
                "The UI closed unexpectedly and the hidden root process was still running.\n"
                + "\n".join(child_states),
            )
            return

        root.after(1000, monitor_visible_windows)

    append_runtime_log("Driver.startup_window", "Creating startup window.")
    root._startup_window = StartupWindow(master=root, on_ready=open_login)
    root.after(1500, monitor_visible_windows)
    root.mainloop()

if __name__ == "__main__":
    main()
