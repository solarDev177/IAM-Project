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
            LoginWindow(master=root)

    StartupWindow(master=root, on_ready=open_login)
    root.mainloop()

if __name__ == "__main__":
    main()
