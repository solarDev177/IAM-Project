# Cloudflare IAM Explorer
# login page


from main_app import App
from tkinter import messagebox

def get_account_ID():
    pass

def verify_account_ID():
    pass

def main():

    try:
        App().mainloop()
    except Exception as e:
        messagebox.showerror("Fatal error", str(e))

if __name__ == '__main__':
    main()
