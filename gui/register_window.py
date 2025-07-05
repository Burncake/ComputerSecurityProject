import tkinter as tk
from tkinter import messagebox
from PIL import ImageTk
import re
import pyotp
from modules.utils.db_helper import insert_user, user_exists
from modules.utils.crypto_helper import hash_passphrase
from modules.utils.otp_helper import generate_totp_secret, get_qr_image_uri, generate_qr_image


class RegisterWindow:
    def __init__(self, master):
        self.root = master
        self.top = tk.Toplevel(master)
        self.top.title("Register New User")
        self.top.geometry("400x400")
        self.top.resizable(False, False)

        # Frame: Form Entry
        self.frame_form = tk.Frame(self.top)
        self.frame_form.pack()

        tk.Label(self.frame_form, text="Username:").pack(pady=5)
        self.entry_username = tk.Entry(self.frame_form, width=40)
        self.entry_username.pack(pady=5)

        tk.Label(self.frame_form, text="Email:").pack(pady=5)
        self.entry_email = tk.Entry(self.frame_form, width=40)
        self.entry_email.pack(pady=5)

        tk.Label(self.frame_form, text="Passphrase:").pack(pady=5)
        self.entry_passphrase = tk.Entry(self.frame_form, width=40, show="*")
        self.entry_passphrase.pack(pady=5)

        tk.Label(self.frame_form, text="Confirm Passphrase:").pack(pady=5)
        self.entry_confirm = tk.Entry(self.frame_form, width=40, show="*")
        self.entry_confirm.pack(pady=5)

        # Show/hide passphrase checkbox
        self.show_var = tk.IntVar()
        chk = tk.Checkbutton(self.frame_form, text="Show Passphrase", variable=self.show_var, command=self.toggle_passphrase)
        chk.pack(pady=5)

        tk.Button(self.frame_form, text="Continue", command=self.prepare_totp).pack(pady=20)
        tk.Button(self.frame_form, text="Cancel", command=self.top.destroy).pack()

        # Frame: QR Code
        self.frame_qr = tk.Frame(self.top)

        # Frame: Verify TOTP
        self.frame_verify = tk.Frame(self.top)

    def toggle_passphrase(self):
        if self.show_var.get():
            self.entry_passphrase.config(show="")
            self.entry_confirm.config(show="")
        else:
            self.entry_passphrase.config(show="*")
            self.entry_confirm.config(show="*")

    def prepare_totp(self):
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

        # Store temporary for later
        self.username = username
        self.email = email
        self.passphrase = passphrase

        # Generate TOTP
        self.totp_secret = generate_totp_secret()
        uri = get_qr_image_uri(self.totp_secret, username)
        qr_img = generate_qr_image(uri)
        self.qr_image = ImageTk.PhotoImage(qr_img)

        # Switch UI to QR frame
        self.frame_form.pack_forget()
        self.show_qr_frame()

    def show_qr_frame(self):
        self.frame_verify.pack_forget()
        self.top.geometry("600x700")

        for widget in self.frame_qr.winfo_children():
            widget.destroy()

        tk.Label(self.frame_qr, text="Scan this QR code in your Authenticator app.").pack(pady=10)
        tk.Label(self.frame_qr, image=self.qr_image).pack()

        tk.Button(self.frame_qr, text="Next: Verify OTP", command=self.show_verify_frame).pack(pady=20)
        tk.Button(self.frame_qr, text="Back", command=self.back_to_form).pack()

        self.frame_qr.pack()

    def show_verify_frame(self):
        self.frame_qr.pack_forget()
        self.top.geometry("400x300")

        for widget in self.frame_verify.winfo_children():
            widget.destroy()

        tk.Label(self.frame_verify, text="Enter two consecutive OTP codes:").pack(pady=10)
        tk.Label(self.frame_verify, text="First OTP:").pack()
        self.otp_entry1 = tk.Entry(self.frame_verify, width=20)
        self.otp_entry1.pack(pady=5)

        tk.Label(self.frame_verify, text="Second OTP:").pack()
        self.otp_entry2 = tk.Entry(self.frame_verify, width=20)
        self.otp_entry2.pack(pady=5)

        tk.Button(self.frame_verify, text="Verify & Register", command=self.verify_otp_and_register).pack(pady=20)
        tk.Button(self.frame_verify, text="Back to QR Code", command=self.show_qr_frame).pack()

        self.frame_verify.pack()

    def back_to_form(self):
        self.top.geometry("400x400")
        self.frame_qr.pack_forget()
        self.frame_form.pack()

    def verify_otp_and_register(self):
        otp1 = self.otp_entry1.get().strip()
        otp2 = self.otp_entry2.get().strip()

        if not otp1 or not otp2:
            messagebox.showerror("Error", "Please enter both OTP codes.")
            return

        totp = pyotp.TOTP(self.totp_secret)
        # Check first OTP
        if not totp.verify(otp1, valid_window=1):
            messagebox.showerror("Error", "First OTP invalid.")
            return

        # Check second OTP
        if not totp.verify(otp2, valid_window=1):
            messagebox.showerror("Error", "Second OTP invalid.")
            return

        # Hash passphrase
        hash_b64, salt_b64 = hash_passphrase(self.passphrase)

        # Insert into DB
        insert_user(self.username, self.email, hash_b64, salt_b64, self.totp_secret)

        messagebox.showinfo("Success", f"User '{self.username}' registered successfully!")
        self.top.destroy()
