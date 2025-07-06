import tkinter as tk
from tkinter import messagebox
from tkcalendar import DateEntry
import re
from modules.core import session
from modules.utils.db_helper import (
    get_user_profile,
    update_user_profile,
    update_user_passphrase,
    get_user_auth_info,
)
from modules.utils.crypto_helper import hash_passphrase
from modules.utils import logger
import pyotp

class AccountUpdateFrame(tk.Frame):
    def __init__(self, master, back_callback):
        super().__init__(master)
        self.back_callback = back_callback
        self.master.geometry("600x500")
        self.pack()

        # Lấy email user đang login
        self.email = session.get_user()['email']

        # Load dữ liệu user
        user_data = get_user_profile(self.email)
        if user_data:
            full_name, dob, phone, address = user_data
        else:
            full_name, dob, phone, address = "", "", "", ""

        # Frame info update
        self.frame_info = tk.Frame(self)
        self.frame_info.pack()

        tk.Label(self.frame_info, text=f"Update Account ({self.email})", font=("Helvetica", 14)).pack(pady=10)

        tk.Label(self.frame_info, text="Full Name:").pack(pady=5)
        self.entry_fullname = tk.Entry(self.frame_info, width=40)
        self.entry_fullname.pack(pady=5)
        self.entry_fullname.insert(0, full_name)

        tk.Label(self.frame_info, text="Date of Birth:").pack(pady=5)
        self.entry_dob = DateEntry(self.frame_info, width=40, background='darkblue', foreground='white', borderwidth=2, date_pattern='yyyy-mm-dd')
        self.entry_dob.pack(pady=5)
        self.entry_dob.set_date(dob)

        tk.Label(self.frame_info, text="Phone:").pack(pady=5)
        self.entry_phone = tk.Entry(self.frame_info, width=40)
        self.entry_phone.pack(pady=5)
        self.entry_phone.insert(0, phone)

        tk.Label(self.frame_info, text="Address:").pack(pady=5)
        self.entry_address = tk.Entry(self.frame_info, width=40)
        self.entry_address.pack(pady=5)
        self.entry_address.insert(0, address)

        tk.Button(self.frame_info, text="Save Changes", command=self.save_profile).pack(pady=20)
        tk.Button(self.frame_info, text="Change Passphrase", command=self.show_change_passphrase_frame).pack(pady=20)
        tk.Button(self.frame_info, text="Back", command=self.back).pack()

        # Frame change passphrase
        self.frame_change_pass = tk.Frame(self)

        # Frame OTP verify
        self.frame_otp_verify = tk.Frame(self)

    def save_profile(self):
        full_name = self.entry_fullname.get().strip()
        dob = self.entry_dob.get().strip()
        phone = self.entry_phone.get().strip()
        address = self.entry_address.get().strip()

        update_user_profile(self.email, full_name, dob, phone, address)

        logger.log_info(f"User '{self.email}' updated profile info.")
        messagebox.showinfo("Success", "Profile updated successfully.")

    def show_change_passphrase_frame(self):
        self.master.geometry("600x300")
        self.frame_info.pack_forget()

        for widget in self.frame_change_pass.winfo_children():
            widget.destroy()

        tk.Label(self.frame_change_pass, text="Enter New Passphrase").pack(pady=5)
        self.entry_new_pass = tk.Entry(self.frame_change_pass, width=40, show="*")
        self.entry_new_pass.pack(pady=5)

        tk.Label(self.frame_change_pass, text="Confirm New Passphrase").pack(pady=5)
        self.entry_confirm_pass = tk.Entry(self.frame_change_pass, width=40, show="*")
        self.entry_confirm_pass.pack(pady=5)

        self.show_var = tk.IntVar()
        chk = tk.Checkbutton(self.frame_change_pass, text="Show Passphrase", variable=self.show_var, command=self.toggle_passphrase_visibility)
        chk.pack(pady=5)

        tk.Button(self.frame_change_pass, text="Next: Verify OTP", command=self.prepare_otp_verify).pack(pady=20)
        tk.Button(self.frame_change_pass, text="Back", command=self.back_to_info).pack()

        self.frame_change_pass.pack()

    def toggle_passphrase_visibility(self):
        if self.show_var.get():
            self.entry_new_pass.config(show="")
            self.entry_confirm_pass.config(show="")
        else:
            self.entry_new_pass.config(show="*")
            self.entry_confirm_pass.config(show="*")

    def prepare_otp_verify(self):
        new_pass = self.entry_new_pass.get()
        confirm = self.entry_confirm_pass.get()

        if not new_pass or not confirm:
            messagebox.showerror("Error", "Please fill in both fields.")
            return

        if new_pass != confirm:
            messagebox.showerror("Error", "Passphrases do not match.")
            return

        if len(new_pass) < 8:
            messagebox.showerror("Error", "Passphrase must be at least 8 characters long.")
            return
        
        if not any(c.isupper() for c in new_pass):
            messagebox.showerror("Error", "Passphrase must contain at least one uppercase letter.")
            return
        
        if not any(c.isdigit() for c in new_pass):
            messagebox.showerror("Error", "Passphrase must contain at least one digit.")
            return
        
        if not bool(re.findall(r"[^a-zA-Z0-9\s]", new_pass)):
            messagebox.showerror("Error", "Passphrase must contain at least one special character.")
            return

        self.new_passphrase = new_pass

        # Move to OTP frame
        self.frame_change_pass.pack_forget()
        self.show_otp_verify_frame()

    def show_otp_verify_frame(self):
        for widget in self.frame_otp_verify.winfo_children():
            widget.destroy()

        tk.Label(self.frame_otp_verify, text="Enter OTP to confirm passphrase change:").pack(pady=10)
        self.entry_otp = tk.Entry(self.frame_otp_verify, width=20)
        self.entry_otp.pack(pady=10)

        tk.Button(self.frame_otp_verify, text="Confirm Change", command=self.verify_otp_and_update_passphrase).pack(pady=20)
        tk.Button(self.frame_otp_verify, text="Back", command=self.back_to_change_passphrase).pack()

        self.frame_otp_verify.pack()

    def verify_otp_and_update_passphrase(self):
        otp_input = self.entry_otp.get().strip()

        # Load user's TOTP secret
        row = get_user_auth_info(self.email)
        if row:
            _, _, totp_secret, _, _ = row
        else:
            messagebox.showerror("Error", "User data not found.")
            return

        totp = pyotp.TOTP(totp_secret)

        if not totp.verify(otp_input, valid_window=1):
            messagebox.showerror("Error", "Invalid OTP.")
            logger.log_warning(f"Failed OTP verification during passphrase change for user '{self.email}'.")
            return

        # Hash passphrase
        hash_b64, salt_b64 = hash_passphrase(self.new_passphrase)

        update_user_passphrase(self.email, hash_b64, salt_b64)

        logger.log_info(f"User '{self.email}' changed passphrase successfully.")
        messagebox.showinfo("Success", "Passphrase changed successfully.")

        self.back()

    def back_to_info(self):
        self.master.geometry("600x500")
        self.frame_change_pass.pack_forget()
        self.frame_info.pack()

    def back_to_change_passphrase(self):
        self.frame_otp_verify.pack_forget()
        self.frame_change_pass.pack()

    def back(self):
        self.pack_forget()
        self.destroy()
        self.back_callback()
