import tkinter as tk
import time
import json
from modules.utils import rsa_key_helper
from modules.utils.db_helper import insert_user_key
from modules.utils.rsa_key_helper import derive_aes_key_from_hash, encrypt_private_key, save_key_to_file, get_public_key_fingerprint
from modules.utils import logger
import os

class KeyCreateFrame(tk.Frame):
    def __init__(self, master, email, passphrase_hash_b64, back_callback, front_callback=None):
        super().__init__(master)
        self.master = master
        self.email = email
        self.passphrase_hash_b64 = passphrase_hash_b64
        self.back_callback = back_callback

        if front_callback:
            self.front_callback = front_callback
        else:
            self.front_callback = back_callback
            
        self.pack()

        self.master.geometry("400x250")
        self.frame_create = tk.Frame(self)
        self.frame_create.pack()

        tk.Label(self.frame_create, text="RSA Key Generation", font=("Helvetica", 14)).pack(pady=10)

        tk.Label(self.frame_create, text="Your account RSA key pair does not exist or has expired.\n"
                                         "Click below to generate your RSA key pair.\n"
                                         "Your private key will be protected with your passphrase.").pack(pady=10)

        tk.Button(self.frame_create, text="Generate Key Pair", command=self.generate_key).pack(pady=20)
        tk.Button(self.frame_create, text="Back", command=self.back).pack()

        # Frame success
        self.frame_success = tk.Frame(self)

    def generate_key(self):
        # Generate RSA key pair
        private_pem, public_pem = rsa_key_helper.generate_rsa_key_pair()

        # Derive AES key
        aes_key, salt = derive_aes_key_from_hash(self.passphrase_hash_b64)

        # Encrypt private key
        encrypted_data = encrypt_private_key(private_pem, aes_key, salt)

        # Save public key
        os.makedirs(f"data/keys/{self.email}", exist_ok=True)
        pub_path = f"data/keys/{self.email}/{self.email}_pub.pem"
        save_key_to_file(pub_path, public_pem)

        # Save encrypted private key
        priv_path = f"data/keys/{self.email}/{self.email}_priv.enc"
        with open(priv_path, "w") as f:
            json.dump(encrypted_data, f)

        # Write key info to DB
        created_at = int(time.time())
        expire_at = created_at + (90 * 24 * 60 * 60)
        insert_user_key(self.email, created_at, expire_at)

        # Log
        logger.log_info(f"User '{self.email}' created RSA key pair.")

        # Switch to success frame
        self.show_success_frame(public_pem, created_at, expire_at)

    def show_success_frame(self, public_pem, created_at, expire_at):
        self.master.geometry("500x250")
        self.frame_create.pack_forget()

        for widget in self.frame_success.winfo_children():
            widget.destroy()

        fingerprint = get_public_key_fingerprint(public_pem)

        tk.Label(self.frame_success, text="Key Created Successfully!", font=("Helvetica", 14)).pack(pady=10)
        tk.Label(self.frame_success, text=f"Fingerprint:\n{fingerprint}").pack(pady=10)

        tk.Label(self.frame_success, text=f"Created At: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(created_at))}").pack()
        tk.Label(self.frame_success, text=f"Expires At: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expire_at))}").pack()

        tk.Button(self.frame_success, text="Done", command=self.front).pack(pady=20)

        self.frame_success.pack()

    def back(self):
        self.pack_forget()
        self.destroy()
        self.back_callback()

    def front(self):
        self.pack_forget()
        self.destroy()
        self.front_callback()