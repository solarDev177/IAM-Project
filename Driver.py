# Cloudflare IAM Explorer
# Driver file

import customtkinter as ctk

from login import LoginWindow
from startup_window import StartupWindow

def main():
    root = ctk.CTk()
    root.withdraw()

    def open_login():
        if root.winfo_exists():
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

    root._startup_window = StartupWindow(master=root, on_ready=open_login)
    root.mainloop()

if __name__ == "__main__":
    main()
