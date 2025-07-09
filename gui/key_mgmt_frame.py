import tkinter as tk
from tkinter import messagebox, filedialog
from modules.core import session
from modules.utils import rsa_key_helper
from modules.utils.db_helper import insert_user_key, get_user_key_info, delete_user_key, get_user_auth_info
from modules.utils import logger
import os
import json
import time
import hashlib

class KeyManagementFrame(tk.Frame):
    def __init__(self, master, back_callback):
        super().__init__(master)
        self.back_callback = back_callback
        self.pack()

        self.email = session.get_user()['email']
        self.passphrase = get_user_auth_info(self.email)[0]

        # Paths
        self.key_dir = os.path.join("data", "keys")
        os.makedirs(self.key_dir, exist_ok=True)

        self.pub_path = os.path.join(self.key_dir, f"{self.email}_pub.pem")
        self.priv_path = os.path.join(self.key_dir, f"{self.email}_priv.enc")

        # Check if key exists
        row = get_user_key_info(self.email)
        if row:
            created_at, expire_at = row
            if time.time() > expire_at:
                self.show_expired_notice()
            else:
                self.show_key_management()
        else:
            self.show_create_key()

    def show_expired_notice(self):
        for widget in self.winfo_children():
            widget.destroy()

        tk.Label(self, text="Your RSA key has expired.", fg="red").pack(pady=10)
        tk.Button(self, text="Generate New Key", command=self.create_key).pack(pady=10)
        tk.Button(self, text="Back", command=self.back).pack(pady=10)

    def show_create_key(self):
        for widget in self.winfo_children():
            widget.destroy()

        tk.Label(self, text="No RSA Key found. Please generate your key.").pack(pady=10)
        tk.Button(self, text="Generate RSA Key", command=self.create_key).pack(pady=10)
        tk.Button(self, text="Back", command=self.back).pack(pady=10)

    def create_key(self):
        private_pem, public_pem = rsa_key_helper.generate_rsa_key_pair()

        # Encrypt private key with user's passphrase
        enc_data = rsa_key_helper.encrypt_private_key(private_pem, self.passphrase)
        enc_json = json.dumps(enc_data)

        # Save files
        rsa_key_helper.save_key_to_file(self.pub_path, public_pem)
        rsa_key_helper.save_key_to_file(self.priv_path, enc_json)

        # Save expiry
        created_at = int(time.time())
        expire_at = created_at + 90 * 24 * 60 * 60
        insert_user_key(self.email, created_at, expire_at)

        logger.log_info(f"User '{self.email}' generated new RSA key pair.")

        messagebox.showinfo("Success", "RSA key pair generated successfully.")
        self.show_key_management()

    def show_key_management(self):
        for widget in self.winfo_children():
            widget.destroy()

        tk.Label(self, text=f"RSA Key Management for {self.email}", font=("Helvetica", 14)).pack(pady=10)

        tk.Button(self, text="View Public Key", command=self.view_public_key).pack(pady=5)
        tk.Button(self, text="View Fingerprint", command=self.view_fingerprint).pack(pady=5)
        tk.Button(self, text="Download Keys", command=self.download_keys).pack(pady=5)
        tk.Button(self, text="Regenerate Key Pair", command=self.confirm_regenerate_key).pack(pady=10)
        tk.Button(self, text="Back", command=self.back).pack(pady=10)

    def view_public_key(self):
        pub_pem = rsa_key_helper.load_key_from_file(self.pub_path)
        top = tk.Toplevel(self)
        top.title("Public Key")
        text = tk.Text(top, wrap="word", width=80, height=20)
        text.insert("1.0", pub_pem)
        text.pack()

    def view_fingerprint(self):
        pub_pem = rsa_key_helper.load_key_from_file(self.pub_path)
        pub_bytes = pub_pem.encode()
        fingerprint = hashlib.sha256(pub_bytes).hexdigest()

        messagebox.showinfo("Fingerprint", f"SHA-256 Fingerprint:\n{fingerprint}")

    def download_keys(self):
        # Let user pick folder
        folder = filedialog.askdirectory()
        if not folder:
            return

        # Copy both files
        pub_data = rsa_key_helper.load_key_from_file(self.pub_path)
        priv_data = rsa_key_helper.load_key_from_file(self.priv_path)

        pub_out = os.path.join(folder, f"{self.email}_pub.pem")
        priv_out = os.path.join(folder, f"{self.email}_priv.enc")

        rsa_key_helper.save_key_to_file(pub_out, pub_data)
        rsa_key_helper.save_key_to_file(priv_out, priv_data)

        messagebox.showinfo("Downloaded", f"Keys saved to:\n{pub_out}\n{priv_out}")

    def confirm_regenerate_key(self):
        res = messagebox.askyesno("Regenerate Key", "Are you sure you want to generate a new RSA key pair? This will overwrite your current keys.")
        if res:
            delete_user_key(self.email)
            os.remove(self.pub_path)
            os.remove(self.priv_path)
            logger.log_info(f"User '{self.email}' deleted old RSA key pair.")
            self.show_create_key()

    def back(self):
        self.pack_forget()
        self.destroy()
        self.back_callback()
