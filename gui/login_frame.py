import tkinter as tk
from tkinter import messagebox
import base64
import pyotp
import time
from datetime import datetime

from modules.utils.db_helper import (
    user_exists,
    get_user_auth_info,
    get_user_profile,
    update_fail_count,
    reset_fail_count,
)
from modules.utils.crypto_helper import hash_passphrase
from modules.core import session
from modules.utils import logger

class LoginFrame(tk.Frame):
    def __init__(self, master, back_callback):
        super().__init__(master)
        self.back_callback = back_callback
        self.master.geometry("400x280")
        self.pack()

        # Frame login info
        self.frame_login = tk.Frame(self)
        self.frame_login.pack()

        tk.Label(self.frame_login, text="Email:").pack(pady=5)
        self.entry_email = tk.Entry(self.frame_login, width=40)
        self.entry_email.pack(pady=5)

        tk.Label(self.frame_login, text="Passphrase:").pack(pady=5)
        self.entry_passphrase = tk.Entry(self.frame_login, width=40, show="*")
        self.entry_passphrase.pack(pady=5)

        self.show_var = tk.IntVar()
        chk = tk.Checkbutton(self.frame_login, text="Show Passphrase", variable=self.show_var, command=self.toggle_passphrase)
        chk.pack(pady=5)

        tk.Button(self.frame_login, text="Login", command=self.verify_passphrase).pack(pady=20)
        tk.Button(self.frame_login, text="Back", command=self.back).pack()

        # Frame OTP
        self.frame_otp = tk.Frame(self)

    def toggle_passphrase(self):
        if self.show_var.get():
            self.entry_passphrase.config(show="")
        else:
            self.entry_passphrase.config(show="*")

    def verify_passphrase(self):
        email = self.entry_email.get().strip()
        passphrase = self.entry_passphrase.get()

        if not email or not passphrase:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        if not user_exists(email):
            messagebox.showerror("Error", f"User '{email}' does not exist.")
            return

        row = get_user_auth_info(email)
        if row:
            stored_hash_b64, salt_b64, totp_secret, fail_count, lock_until = row

            current_time = int(time.time())
            if lock_until:
                if current_time < lock_until:
                    minutes = int((lock_until - current_time) / 60) + 1
                    lock_time_str = datetime.fromtimestamp(lock_until).strftime("%Y-%m-%d %H:%M:%S")
                    messagebox.showerror("Account Locked", f"Account is locked. Try again in {minutes} minutes.")
                    logger.log_warning(f"Login blocked for user '{email}'. Account is locked until {lock_time_str}.")
                    return
                else:
                    # Lock expired → reset
                    reset_fail_count(email)
                    fail_count = 0
                    lock_until = None
                    logger.log_info(f"Lock expired for user '{email}'. fail_count reset.")

            salt = base64.b64decode(salt_b64)
            input_hash_b64, _ = hash_passphrase(passphrase, salt)

            if input_hash_b64 == stored_hash_b64:
                # Save temp data for OTP step
                self.email = email
                self.totp_secret = totp_secret
                self.show_otp_frame()
            else:
                fail_count += 1
                lock_time = None
                if fail_count >= 5:
                    lock_time = int(time.time()) + (5 * 60)
                    messagebox.showerror("Account Locked", "Too many failed attempts. Account locked for 5 minutes.")
                else:
                    messagebox.showerror("Error", f"Incorrect passphrase. Attempt {fail_count}/5.")

                update_fail_count(email, fail_count, lock_time)
                logger.log_warning(f"Failed login attempt for user '{email}' - wrong passphrase. Attempt {fail_count}/5.")
                return
        else:
            messagebox.showerror("Error", "User not found.")

    def show_otp_frame(self):
        self.frame_login.pack_forget()
        self.master.geometry("400x185")

        for widget in self.frame_otp.winfo_children():
            widget.destroy()

        tk.Label(self.frame_otp, text=f"Enter OTP for {self.email}:").pack(pady=10)

        self.otp_entry = tk.Entry(self.frame_otp, width=20)
        self.otp_entry.pack(pady=10)

        tk.Button(self.frame_otp, text="Confirm", command=self.verify_otp).pack(pady=10)
        tk.Button(self.frame_otp, text="Back to Login", command=self.back_to_login).pack()

        self.frame_otp.pack()

    def back_to_login(self):
        self.master.geometry("400x280")
        self.frame_otp.pack_forget()
        self.frame_login.pack()

    def verify_otp(self):
        otp = self.otp_entry.get().strip()

        row = get_user_auth_info(self.email)
        if row:
            _, _, _, fail_count, lock_until = row

            current_time = int(time.time())
            if lock_until:
                if current_time < lock_until:
                    minutes = int((lock_until - current_time) / 60) + 1
                    lock_time_str = datetime.fromtimestamp(lock_until).strftime("%Y-%m-%d %H:%M:%S")
                    messagebox.showerror("Account Locked", f"Account is locked. Try again in {minutes} minutes.")
                    logger.log_warning(f"Login blocked for user '{self.email}'. Account is locked until {lock_time_str}.")
                    return
                else:
                    # Lock expired → reset
                    reset_fail_count(self.email)
                    fail_count = 0
                    lock_until = None
                    logger.log_info(f"Lock expired for user '{self.email}'. fail_count reset.")

        if not otp:
            messagebox.showerror("Error", "Please enter the OTP.")
            return

        totp = pyotp.TOTP(self.totp_secret)
        if totp.verify(otp, valid_window=1):
            reset_fail_count(self.email)

            # Save session
            user_obj = {
                "email": self.email,
                "full_name": get_user_profile(self.email)[0],
            }
            session.login_user(user_obj)

            logger.log_info(f"User '{self.email}' logged in successfully.")
            messagebox.showinfo("Success", f"Login successful! Welcome, {self.email}.")
            self.back()
        else:
            fail_count += 1
            lock_time = None
            if fail_count >= 5:
                lock_time = int(time.time()) + (5 * 60)
                messagebox.showerror("Account Locked", "Too many failed attempts. Account locked for 5 minutes.")
            else:
                messagebox.showerror("Error", f"Invalid OTP. Attempt {fail_count}/5.")

            update_fail_count(self.email, fail_count, lock_time)
            logger.log_warning(f"Failed OTP login attempt for user '{self.email}'. Attempt {fail_count}/5.")
            return

    def back(self):
        self.pack_forget()
        self.destroy()
        self.back_callback()
