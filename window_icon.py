"""Helpers for applying the shared window icon across the desktop app."""

from pathlib import Path
import tkinter as tk


class WindowIconManager:
    """Applies the shared application icon to Tk and CustomTkinter windows."""

    _ICON_IMAGE = None
    _ICON_ICO_PATH = Path(__file__).resolve().parent / "assets" / "cloudflare_app.ico"
    _ICON_PNG_BASE64 = (
        "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAA70lEQVR42u2ayw2DMBAFaSZdpRhKSnM5O8oBiUOkYLOf"
        "t/aM5KthRgJsYNsAAAAAAAAgl/f+aFMLtteznWWvjrKyV8dUIXrEpwtxR758BAv5shEs5ctF8JDviTCtfIkISweIkJeOo"
        "BYgPIRqgLAQ6gFcI3wnrxDAJUK0vFyEY9KMCOn3g/OkWQFGQ5jKKwQIfzwSQDBA6K7x16RL3QeqBzCXr/Y4dLkEMiKkLYb"
        "+HUBl1ZcWwCqCpHzPlxw1+fAAIyG8xN02QqPDWzbkfUCkgJx8hQBh3/GXlVeLIPFXR7mTzozA/z4AAAAAAAAA6XwAWXGmI"
        "P4Cs64AAAAASUVORK5CYII="
    )

    @classmethod
    def _apply_now(cls, window) -> None:
        """Apply the shared icon to the provided window immediately."""
        if window is None or not hasattr(window, "winfo_exists") or not window.winfo_exists():
            return

        try:
            if cls._ICON_IMAGE is None:
                cls._ICON_IMAGE = tk.PhotoImage(data=cls._ICON_PNG_BASE64)
            if cls._ICON_ICO_PATH.exists():
                icon_path = str(cls._ICON_ICO_PATH)
                window.iconbitmap(default=icon_path)
                try:
                    window.wm_iconbitmap(icon_path)
                except Exception:
                    pass
            window.iconphoto(True, cls._ICON_IMAGE)
            window._app_icon_ref = cls._ICON_IMAGE
        except Exception:
            pass

    @classmethod
    def apply(cls, window) -> None:
        """Apply the shared icon and retry shortly for newly-created child windows."""
        cls._apply_now(window)

        if window is None or not hasattr(window, "after") or not hasattr(window, "winfo_exists"):
            return

        for delay_ms in (60, 180, 420):
            try:
                window.after(delay_ms, lambda target=window: cls._apply_now(target))
            except Exception:
                break
