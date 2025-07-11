import tkinter as tk
from tkinter import filedialog, messagebox
import os
import json
import base64
from modules.core import session
from modules.utils import logger
from modules.utils.file_crypto_helper import decrypt_file_for_user
from modules.utils.db_helper import get_user_auth_info
from modules.utils.rsa_key_helper import derive_aes_key_from_hash, decrypt_private_key

class DecryptFrame(tk.Frame):
    def __init__(self, master, back_callback):
        super().__init__(master)
        self.back_callback = back_callback
        self.pack(padx=20, pady=20)

        if not session.is_logged_in():
            messagebox.showerror("Error", "You must be logged in to decrypt files.")
            return

        self.email = session.get_user()['email']

        tk.Label(self, text="Decrypt Received File", font=("Helvetica", 14)).pack(pady=10)

        # Encrypted file chooser
        self.encpath = tk.StringVar()
        tk.Button(self, text="Choose .enc File…", command=self.choose_enc).pack(fill="x")
        tk.Entry(self, textvariable=self.encpath, state="readonly").pack(fill="x", pady=5)

        # Optional .key chooser
        self.keypath = tk.StringVar()
        self.key_button = tk.Button(self, text="(Optional) Choose .key File…", command=self.choose_key)
        self.key_button.pack(fill="x")
        self.key_entry = tk.Entry(self, textvariable=self.keypath, state="readonly")
        self.key_entry.pack(fill="x", pady=5)
        # Passphrase entry
        tk.Label(self, text="Your Passphrase:").pack(pady=5)
        self.entry_pass = tk.Entry(self, width=40, show="*")
        self.entry_pass.pack()

        # Buttons
        tk.Button(self, text="Decrypt & Save", command=self.do_decrypt).pack(pady=15)
        tk.Button(self, text="Back", command=self.back_callback).pack()

    def choose_enc(self):
        path = filedialog.askopenfilename(filetypes=[("ENC files", "*.enc")])
        if not path:
            return
        self.encpath.set(path)

        # Detect combined vs separate
        try:
            with open(path, "r") as f:
                data = json.load(f)
            combined_mode = "encrypted_session_key" in data
        except Exception:
            combined_mode = False

        if combined_mode:
            # Combined: disable key chooser
            self.key_button.config(state="disabled")
            self.key_entry.config(state="disabled")
            self.keypath.set("")  # clear any previous key
        else:
            # Separate: enable key chooser
            self.key_button.config(state="normal")
            self.key_entry.config(state="readonly")

    def choose_key(self):
        path = filedialog.askopenfilename(filetypes=[("KEY files", "*.key")])
        if path:
            self.keypath.set(path)

    def do_decrypt(self):
        enc = self.encpath.get()
        key = self.keypath.get() or None
        pw = self.entry_pass.get().strip()

        # 1. Basic input validation
        if not enc or not os.path.isfile(enc):
            messagebox.showerror("Error", "Please choose a valid .enc file.")
            return

        # 2. Detect if .enc file is in combined mode or separate mode
        try:
            with open(enc, "r") as f:
                enc_json = json.load(f)
        except Exception:
            messagebox.showerror("Error", "Cannot read .enc file (not a valid JSON).")
            return

        combined_mode = "encrypted_session_key" in enc_json

        # 3. If separate mode, check if key file is provided
        if not combined_mode and not key:
            messagebox.showerror(
                "Error",
                "This encrypted file requires a separate .key file.\n"
                "Please choose the corresponding .key session key file."
            )
            return

        # 4. Load & decrypt RSA private key
        row = get_user_auth_info(self.email)
        if not row:
            messagebox.showerror("Error", "User info not found. Please log in again.")
            return
        stored_hash_b64, stored_salt_b64, totp_secret, _, _ = row

        # Decrypt private key file
        try:
            priv_enc_path = f"data/keys/{self.email}/{self.email}_priv.enc"
            with open(priv_enc_path, "r") as f:
                pk_enc = json.load(f)

            salt = base64.b64decode(pk_enc["salt"])
            old_aes_key, _ = derive_aes_key_from_hash(stored_hash_b64, salt)
            private_pem = decrypt_private_key(pk_enc, old_aes_key)
            if not private_pem:
                raise ValueError("Wrong passphrase for private key.")
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            return
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load/decrypt your private key:\n{e}")
            return

        # 5. Save decrypted file
        out = filedialog.asksaveasfilename(
            defaultextension="",
            initialfile=os.path.splitext(os.path.basename(enc))[0]
        )
        if not out:
            return

        # 6. Decrypt the file
        try:
            decrypted_path = decrypt_file_for_user(
                receiver_priv_pem=private_pem,
                passphrase=None,
                encrypted_path=enc,
                key_path=key,
                output_filepath=out
            )
            messagebox.showinfo("Success", f"File decrypted to:\n{decrypted_path}")
            self.back_callback()
        except FileNotFoundError as e:
            messagebox.showerror("Error", f"File not found:\n{e}")
        except ValueError as e:
            # AES GCM failed verify -> ciphertext/tag mismatch
            messagebox.showerror("Error", "Decryption failed: data corrupted or wrong key.")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed:\n{e}")
