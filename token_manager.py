# Cloudflare IAM Explorer
# main app

import customtkinter as ctk
from tkinter import messagebox
from token_store import TokenStore

class TokenManagerWindow(ctk.CTkToplevel):
    def __init__(self, master=None, on_saved=None):
        super().__init__(master)
        self.title("Manage Tokens")
        self.geometry("650x420")
        self.resizable(False, False)
        self.on_saved = on_saved

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

        self.entries = {}
        row = 2
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
                      fg_color="#0078d4", hover_color="#106ebe").pack(side="left", padx=(0, 10))
        ctk.CTkButton(btns, text="Close", command=self.destroy,
                      fg_color="#333333", hover_color="#444444").pack(side="left")

    def save(self):
        # commit current edit:
        self.focus_set()

        tokens = {k: self.entries[k].get().strip() for k in self.store.TOKEN_TYPES}

        self.store.save(tokens)
        messagebox.showinfo("Saved", "Tokens saved locally.")
        if self.on_saved:
            self.on_saved(tokens)
