# Cloudflare IAM Explorer
# main app

import customtkinter as ctk
from tkinter import messagebox
from token_store import TokenStore
from window_icon import WindowIconManager

class TokenManagerWindow(ctk.CTkToplevel):
    def __init__(self, master=None, on_saved=None):
        super().__init__(master)
        self.title("Manage Tokens")
        self.geometry("760x560")
        self.resizable(False, False)
        self.on_saved = on_saved
        WindowIconManager.apply(self)

        if master is not None:
            self.transient(master)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.configure(fg_color="#000000")

        self.store = TokenStore()
        existing = self.store.load()

        frame = ctk.CTkFrame(self, fg_color="#000000")
        frame.pack(fill="both", expand=True, padx=18, pady=18)

        ctk.CTkLabel(frame, text="Saved tokens (stored locally)", text_color="#ffffff",
                     font=("Segoe UI", 18, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))

        ctk.CTkLabel(frame, text=f"File: {self.store.path()}", text_color="#a0a0a0",
                     font=("Segoe UI", 11)).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 16))

        tips = ctk.CTkFrame(frame, fg_color="#111111", corner_radius=10)
        tips.grid(row=2, column=0, columnspan=2, sticky="we", pady=(0, 16))
        tips.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            tips,
            text="Recommended Cloudflare Tokens",
            text_color="#ffffff",
            font=("Segoe UI", 14, "bold"),
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        ctk.CTkLabel(
            tips,
            text=(
                "Create these API tokens in Cloudflare before importing them here:\n"
                "Account Read  -> AccountReadToken  | Permission: Account.Account Settings | Resource: 1 Account\n"
                "Account Edit  -> AccountWriteToken | Permission: Account.Account Settings | Resource: 1 Account\n"
                "Group Read    -> GroupReadToken    | Permission: Account.SCIM Provisioning | Resource: 1 Account\n"
                "Group Edit    -> GroupEditToken    | Permission: Account.SCIM Provisioning | Resource: 1 Account"
            ),
            text_color="#d0d0d0",
            justify="left",
            anchor="w",
            wraplength=680,
            font=("Segoe UI", 11),
        ).grid(row=1, column=0, sticky="w", padx=12, pady=(0, 8))

        ctk.CTkLabel(
            tips,
            text="Tip: Group Read and Group Edit can use separate SCIM tokens, or the same SCIM token if you prefer.",
            text_color="#ff9f1c",
            justify="left",
            anchor="w",
            wraplength=680,
            font=("Segoe UI", 11, "italic"),
        ).grid(row=2, column=0, sticky="w", padx=12, pady=(0, 12))

        self.entries = {}
        row = 3
        for t in self.store.TOKEN_TYPES:

            ctk.CTkLabel(frame, text=t, text_color="#ffffff").grid(row=row, column=0, sticky="w", pady=6)

            entry = ctk.CTkEntry(
                frame,
                width=420,
                show="•",
                fg_color="#1a1a1a",
                border_color="#333333",
                text_color="#ffffff")

            entry.grid(row=row, column=1, sticky="w", pady=6)
            entry.insert(0, existing.get(t, ""))
            self.entries[t] = entry
            row += 1

        btns = ctk.CTkFrame(frame, fg_color="#000000")
        btns.grid(row=row, column=0, columnspan=2, sticky="w", pady=(18, 0))

        ctk.CTkButton(btns, text="Save", command=self.save,
                      fg_color="#ff8c1a", hover_color="#ff9f1c").pack(side="left", padx=(0, 10))
        ctk.CTkButton(btns, text="Close", command=self.destroy,
                      fg_color="#333333", hover_color="#444444").pack(side="left")

        self.after(0, self._bring_to_front)

    def _bring_to_front(self):
        """Bring the token manager above the main application window."""
        try:
            self.lift()
            self.focus_force()
            self.attributes("-topmost", True)
            self.after(150, lambda: self.winfo_exists() and self.attributes("-topmost", False))
        except Exception:
            pass

    def save(self):
        # commit current edit:
        self.focus_set()

        tokens = {k: self.entries[k].get().strip() for k in self.store.TOKEN_TYPES}

        self.store.save(tokens)
        messagebox.showinfo("Saved", "Tokens saved locally.")
        if self.on_saved:
            self.on_saved(tokens)
