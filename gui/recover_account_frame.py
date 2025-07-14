import tkinter as tk
from tkinter import messagebox
from PIL import ImageTk
import base64, json, re, pyotp
from modules.utils import logger
from modules.utils.db_helper import get_recovery_code_hash, get_user_auth_info, update_user_passphrase, update_user_totp
from modules.utils.crypto_helper import hash_passphrase, hash_recovery_code
from modules.utils.rsa_key_helper import derive_aes_key_from_hash, decrypt_private_key, encrypt_private_key
from modules.utils.otp_helper import generate_totp_secret, get_qr_image_uri, generate_qr_image

class RecoverAccountFrame(tk.Frame):
    def __init__(self, master, back_callback):
        super().__init__(master)
        self.master = master
        self.master.geometry("400x425")
        self.back_callback = back_callback
        self.pack()

        self.frame_form = tk.Frame(self)
        self.frame_form.pack()

        tk.Label(self.frame_form, text="Recover Account", font=("Helvetica", 14, "bold")).pack(pady=20)
        
        tk.Label(self.frame_form, text="Email").pack()
        self.entry_email = tk.Entry(self.frame_form, width=40)
        self.entry_email.pack(pady=5)

        tk.Label(self.frame_form, text="Recovery Code").pack()
        self.entry_rc = tk.Entry(self.frame_form, width=40)
        self.entry_rc.pack(pady=5)

        tk.Label(self.frame_form, text="New Passphrase").pack()
        self.entry_pass = tk.Entry(self.frame_form, width=40, show="*")
        self.entry_pass.pack(pady=5)

        tk.Label(self.frame_form, text="Confirm New Passphrase").pack()
        self.entry_pass_confirm = tk.Entry(self.frame_form, width=40, show="*")
        self.entry_pass_confirm.pack(pady=5)

        self.show_var = tk.IntVar()
        chk = tk.Checkbutton(self.frame_form, text="Show Passphrase", variable=self.show_var, command=self.toggle_passphrase)
        chk.pack(pady=5)

        tk.Button(self.frame_form, text="Recover", command=self.recover).pack(pady=15)
        tk.Button(self.frame_form, text="Back", command=self.back_callback).pack()

        self.frame_qr = tk.Frame(self)
        self.frame_verify = tk.Frame(self)

    def toggle_passphrase(self):
        if self.show_var.get():
            self.entry_pass.config(show="")
            self.entry_pass_confirm.config(show="")
        else:
            self.entry_pass.config(show="*")
            self.entry_pass_confirm.config(show="*")

    def recover(self):
        email = self.entry_email.get().strip()
        rc = self.entry_rc.get().strip()
        new_pw = self.entry_pass.get().strip()
        new_pw_conf = self.entry_pass_confirm.get().strip()

        if not email or not rc or not new_pw or not new_pw_conf:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        if new_pw != new_pw_conf:
            messagebox.showerror("Error", "New passphrases do not match.")
            return
        
        if len(new_pw) < 8:
            messagebox.showerror("Error", "Passphrase must be at least 8 characters long.")
            return
        
        if not any(c.isupper() for c in new_pw):
            messagebox.showerror("Error", "Passphrase must contain at least one uppercase letter.")
            return
        
        if not any(c.isdigit() for c in new_pw):
            messagebox.showerror("Error", "Passphrase must contain at least one digit.")
            return
        
        if not bool(re.findall(r"[^a-zA-Z0-9\s]", new_pw)):
            messagebox.showerror("Error", "Passphrase must contain at least one special character.")
            return

        # Step 1: check recovery code
        stored_hash = get_recovery_code_hash(email)
        if not stored_hash:
            messagebox.showerror("Error", "No recovery code found for this email.")
            return

        hash_input = hash_recovery_code(rc)
        if stored_hash != hash_input:
            messagebox.showerror("Error", "Invalid recovery code.")
            return

        # Step 2: load encrypted private key
        try:
            priv_enc_path = f"data/keys/{email}/{email}_priv.enc"
            with open(priv_enc_path, "r") as f:
                enc_data = json.load(f)
        except FileNotFoundError:
            messagebox.showerror("Error", "Private key file missing.")
            return

        # Step 3: decrypt private key with old passphrase
        row = get_user_auth_info(email)
        if not row:
            messagebox.showerror("Error", "User not found.")
            return

        stored_hash_b64, stored_salt_b64, _, _, _ = row
        salt = base64.b64decode(enc_data["salt"])
        old_aes_key, _ = derive_aes_key_from_hash(stored_hash_b64, salt)

        priv_pem = decrypt_private_key(enc_data, old_aes_key)
        if priv_pem is None:
            messagebox.showwarning(
                "Warning",
                "Cannot decrypt your private key with old passphrase.\n"
                "Your key file may remain inaccessible until admin resets it."
            )
            # For now still allow updating passphrase
            priv_pem = None

        # Step 4: derive new key, re-encrypt private key if possible
        new_hash_b64, new_salt_b64 = hash_passphrase(new_pw)

        if priv_pem:
            new_aes_key, new_salt_enc = derive_aes_key_from_hash(new_hash_b64)
            enc_data_new = encrypt_private_key(priv_pem, new_aes_key, new_salt_enc)
            with open(priv_enc_path, "w") as f:
                json.dump(enc_data_new, f)
            logger.log_info(f"User '{email}' successfully re-encrypted private key with new passphrase via recovery code.")

        # Step 5: update passphrase in DB
        update_user_passphrase(email, new_hash_b64, new_salt_b64)

        logger.log_info(f"User '{email}' successfully recovered account and updated passphrase.")
        messagebox.showinfo("Success", "Your passphrase has been reset successfully.")

        reset = messagebox.askyesno(
            "Reset TOTP",
            "Do you want to reset your TOTP (2FA) as well?\n"
            "You'll scan a new QR code and verify 2 OTPs."
        )
        if reset:
            self.email = email
            self.reset_totp_flow()
        else:
            self.pack_forget()
            self.destroy()
            self.back_callback()

    def reset_totp_flow(self):
        self.frame_form.pack_forget()

        # 1. Generate new secret
        self.totp_secret = generate_totp_secret()
        uri = get_qr_image_uri(self.totp_secret, self.email)
        qr_img = generate_qr_image(uri).resize((250, 250))
        self.qr_image = ImageTk.PhotoImage(qr_img)
        self.show_qr_frame()

    def show_qr_frame(self):
        self.frame_verify.pack_forget()
        self.master.geometry("400x425")

        for widget in self.frame_qr.winfo_children():
            widget.destroy()

        tk.Label(self.frame_qr, text="Scan this QR code with your authenticator app:").pack(pady=10)
        tk.Label(self.frame_qr, image=self.qr_image).pack()

        tk.Button(self.frame_qr, text="Next: Verify OTP", command=self.show_verify_frame).pack(pady=20)

        self.frame_qr.pack()
    
    def show_verify_frame(self):
        self.frame_qr.pack_forget()
        self.master.geometry("400x265")

        for widget in self.frame_verify.winfo_children():
            widget.destroy()

        tk.Label(self.frame_verify, text="Enter two consecutive OTP codes:").pack(pady=10)
        tk.Label(self.frame_verify, text="First OTP:").pack()
        self.otp_entry1 = tk.Entry(self.frame_verify, width=20)
        self.otp_entry1.pack(pady=5)

        tk.Label(self.frame_verify, text="Second OTP:").pack()
        self.otp_entry2 = tk.Entry(self.frame_verify, width=20)
        self.otp_entry2.pack(pady=5)

        tk.Button(self.frame_verify, text="Verify & Register", command=self.verify_otp).pack(pady=20)
        tk.Button(self.frame_verify, text="Back to QR Code", command=self.show_qr_frame).pack()

        self.frame_verify.pack()

    def verify_otp(self):
        otp1 = self.otp_entry1.get().strip()
        otp2 = self.otp_entry2.get().strip()

        if not otp1 or not otp2:
            messagebox.showerror("Error", "Please enter both OTP codes.")
            return

        totp = pyotp.TOTP(self.totp_secret)

        if not totp.verify(otp1, valid_window=1):
            messagebox.showerror("Error", "First OTP invalid.")
            return

        if not totp.verify(otp2, valid_window=1):
            messagebox.showerror("Error", "Second OTP invalid.")
            return
        
        update_user_totp(self.email, self.totp_secret)
        logger.log_info(f"User '{self.email}' successfully reset TOTP after account recovery.")
        messagebox.showinfo("Success", "TOTP has been reset successfully.")

        self.pack_forget()
        self.destroy()
        self.back_callback()