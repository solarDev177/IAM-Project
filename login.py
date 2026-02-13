# Cloudflare IAM Explorer
# login page

import customtkinter as ctk
from main_app import App
from tkinter import messagebox

class LoginWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Cloudflare IAM Login")
        self.geometry("300x150")

def main():

    LoginWindow().mainloop()

if __name__ == "__main__":
    main()
