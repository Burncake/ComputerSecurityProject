import tkinter as tk
from tkinter import messagebox
from modules.utils.db_helper import user_exists, DB_PATH
from modules.utils.crypto_helper import hash_passphrase
import sqlite3
import base64
import pyotp

class LoginWindow:
    def __init__(self, master):
        self.master = master
        self.top = tk.Toplevel(master)
        self.top.title("Login")
        self.top.geometry("400x300")
        self.top.resizable(False, False)

        # Frame for login form
        self.frame_login = tk.Frame(self.top)
        self.frame_login.pack()

        tk.Label(self.frame_login, text="Username:").pack(pady=5)
        self.entry_username = tk.Entry(self.frame_login, width=40)
        self.entry_username.pack(pady=5)

        tk.Label(self.frame_login, text="Passphrase:").pack(pady=5)
        self.entry_passphrase = tk.Entry(self.frame_login, width=40, show="*")
        self.entry_passphrase.pack(pady=5)

        self.show_var = tk.IntVar()
        chk = tk.Checkbutton(self.frame_login, text="Show Passphrase", variable=self.show_var, command=self.toggle_passphrase)
        chk.pack(pady=5)

        tk.Button(self.frame_login, text="Login", command=self.verify_passphrase).pack(pady=20)
        tk.Button(self.frame_login, text="Cancel", command=self.top.destroy).pack()

        # Frame for OTP
        self.frame_otp = tk.Frame(self.top)

    def toggle_passphrase(self):
        if self.show_var.get():
            self.entry_passphrase.config(show="")
        else:
            self.entry_passphrase.config(show="*")

    def verify_passphrase(self):
        username = self.entry_username.get().strip()
        passphrase = self.entry_passphrase.get()

        if not username or not passphrase:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        if not user_exists(username):
            messagebox.showerror("Error", f"Username '{username}' does not exist.")
            return

        # Fetch hash + salt + totp_secret
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT passphrase_hash, salt, totp_secret FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()

        if row:
            stored_hash_b64, salt_b64, totp_secret = row
            salt = base64.b64decode(salt_b64)
            input_hash_b64, _ = hash_passphrase(passphrase, salt)

            if input_hash_b64 == stored_hash_b64:
                # Save data for OTP step
                self.username = username
                self.totp_secret = totp_secret

                # Switch to OTP frame
                self.frame_login.pack_forget()
                self.show_otp_frame()
            else:
                messagebox.showerror("Error", "Incorrect passphrase.")
        else:
            messagebox.showerror("Error", "User not found in DB.")

    def show_otp_frame(self):
        self.top.geometry("400x200")
        for widget in self.frame_otp.winfo_children():
            widget.destroy()

        tk.Label(self.frame_otp, text=f"Enter OTP for {self.username}:").pack(pady=10)

        self.otp_entry = tk.Entry(self.frame_otp, width=20)
        self.otp_entry.pack(pady=10)

        tk.Button(self.frame_otp, text="Confirm", command=self.verify_otp).pack(pady=10)
        tk.Button(self.frame_otp, text="Back to Login", command=self.back_to_login).pack()

        self.frame_otp.pack()

    def back_to_login(self):
        self.top.geometry("400x300")
        self.frame_otp.pack_forget()
        self.frame_login.pack()

    def verify_otp(self):
        otp = self.otp_entry.get().strip()
        if not otp:
            messagebox.showerror("Error", "Please enter the OTP.")
            return

        totp = pyotp.TOTP(self.totp_secret)
        if totp.verify(otp, valid_window=1):
            messagebox.showinfo("Success", f"Login successful! Welcome, {self.username}.")
            self.top.destroy()
        else:
            messagebox.showerror("Error", "Invalid OTP. Please try again.")
