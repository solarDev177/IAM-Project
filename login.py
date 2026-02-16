# Cloudflare IAM Explorer
# login page

import customtkinter as ctk
from tkinter import messagebox


class LoginWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Cloudflare IAM Login")
        self.geometry("500x450")
        self.resizable(False, False)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.configure(fg_color="#1e1e1e")

        self._build_ui()

    def _build_ui(self):
        container = ctk.CTkFrame(self, fg_color="#2d2d2d", corner_radius=10)
        container.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(container,text="Cloudflare IAM Scanner",text_color="#e0e0e0",font=("Segoe UI", 24, "bold")).pack(padx=40, pady=(30, 10))

        ctk.CTkLabel(container,text="Sign in to continue",text_color="#a0a0a0",font=("Segoe UI", 12)).pack(padx=40, pady=(0, 30))

        ctk.CTkLabel(container,text="API Token",text_color="#e0e0e0",font=("Segoe UI", 11, "bold"),anchor="w").pack(padx=40, pady=(10, 5), anchor="w")

        self.token_entry = ctk.CTkEntry(container,width=350,height=40,fg_color="#3c3c3c",border_color="#454545",text_color="#e0e0e0",font=("Segoe UI", 10),placeholder_text="Enter your API token",placeholder_text_color="#707070",show="•")
        self.token_entry.pack(padx=40, pady=(0, 15))

        ctk.CTkLabel(container,text="Account ID",text_color="#e0e0e0",font=("Segoe UI", 11, "bold"),anchor="w").pack(padx=40, pady=(10, 5), anchor="w")

        self.account_id_entry = ctk.CTkEntry(container,width=350,height=40,fg_color="#3c3c3c",border_color="#454545",text_color="#e0e0e0",font=("Segoe UI", 10),placeholder_text="Enter your account ID",placeholder_text_color="#707070")
        self.account_id_entry.pack(padx=40, pady=(0, 25))
        self.account_id_entry.bind("<Return>", lambda e: self._validate_and_login())

        self.login_button = ctk.CTkButton(container,text="Sign In", command=self._validate_and_login,fg_color="#007acc",hover_color="#1a8cd8",text_color="white",font=("Segoe UI", 12, "bold"),width=350,height=45,corner_radius=8)
        self.login_button.pack(padx=40, pady=(0, 30))

    def _validate_and_login(self):
        token = self.token_entry.get().strip()
        account_id = self.account_id_entry.get().strip()

        if not token:
            messagebox.showerror("Error", "API Token is required!")
            return

        if not account_id:
            messagebox.showerror("Error", "Account ID is required!")
            return

        self.login_button.configure(state="disabled", text="Signing in...")
        self.update()

        self.after(300, lambda: self._launch_main_app(account_id, token))

    def _launch_main_app(self, account_id, token):
        self.withdraw()

        from main_app import App
        app = App(account_id=account_id, token=token)

        def on_close():
            app.destroy()
            self.destroy()

        app.protocol("WM_DELETE_WINDOW", on_close)
        app.mainloop()


def main():
    LoginWindow().mainloop()


if __name__ == "__main__":
    main()