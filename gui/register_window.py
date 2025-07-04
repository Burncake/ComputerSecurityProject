import tkinter as tk
from tkinter import messagebox
from modules.utils.db_helper import insert_user, user_exists
from modules.utils.crypto_helper import hash_passphrase
import re

class RegisterWindow:
    def __init__(self, master):
        self.top = tk.Toplevel(master)
        self.top.title("Register New User")
        self.top.geometry("400x400")
        self.top.resizable(False, False)

        tk.Label(self.top, text="Username:").pack(pady=5)
        self.entry_username = tk.Entry(self.top, width=40)
        self.entry_username.pack(pady=5)

        tk.Label(self.top, text="Email:").pack(pady=5)
        self.entry_email = tk.Entry(self.top, width=40)
        self.entry_email.pack(pady=5)

        tk.Label(self.top, text="Passphrase:").pack(pady=5)
        self.entry_passphrase = tk.Entry(self.top, width=40, show="*")
        self.entry_passphrase.pack(pady=5)

        tk.Label(self.top, text="Confirm Passphrase:").pack(pady=5)
        self.entry_confirm = tk.Entry(self.top, width=40, show="*")
        self.entry_confirm.pack(pady=5)

        # Show/hide passphrase checkbox
        self.show_var = tk.IntVar()
        chk = tk.Checkbutton(self.top, text="Show Passphrase", variable=self.show_var, command=self.toggle_passphrase)
        chk.pack(pady=5)

        tk.Button(self.top, text="Register", command=self.register).pack(pady=20)
        tk.Button(self.top, text="Cancel", command=self.top.destroy).pack()

    def toggle_passphrase(self):
        if self.show_var.get():
            self.entry_passphrase.config(show="")
            self.entry_confirm.config(show="")
        else:
            self.entry_passphrase.config(show="*")
            self.entry_confirm.config(show="*")

    def register(self):
        username = self.entry_username.get().strip()
        email = self.entry_email.get().strip()
        passphrase = self.entry_passphrase.get()
        confirm = self.entry_confirm.get()

        if not username or not email or not passphrase or not confirm:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        if passphrase != confirm:
            messagebox.showerror("Error", "Passphrases do not match.")
            return
        
        # If passphrase does not contain at least one uppercase letter, one digit, and one special character or is less than 8 characters
        if len(passphrase) < 8:
            messagebox.showerror("Error", "Passphrase must be at least 8 characters long.")
            return

        if not any(c.isupper() for c in passphrase):
            messagebox.showerror("Error", "Passphrase must contain at least one uppercase letter.")
            return
        
        if not any(c.isdigit() for c in passphrase):
            messagebox.showerror("Error", "Passphrase must contain at least one digit.")
            return
        
        if not bool(re.findall(r"[^a-zA-Z0-9\s]", passphrase)):
            messagebox.showerror("Error", "Passphrase must contain at least one special character.")
            return

        # Check if username already exists
        if user_exists(username):
            messagebox.showerror("Error", f"Username '{username}' already exists.")
            return

        # Hash passphrase
        hash_b64, salt_b64 = hash_passphrase(passphrase)

        # Insert into DB
        insert_user(username, email, hash_b64, salt_b64)

        messagebox.showinfo("Success", f"User '{username}' registered successfully!")

        self.top.destroy()
