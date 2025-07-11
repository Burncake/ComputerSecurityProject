import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import ImageTk, Image
import pyzbar.pyzbar as pyzbar
import time
import json
import base64
import os
import qrcode
from modules.utils.crypto_helper import hash_passphrase
from gui.key_create_frame import KeyCreateFrame
from modules.core import session
from modules.utils.db_helper import get_user_key_info, get_user_auth_info, delete_user_key
from modules.utils.rsa_key_helper import (
    load_key_from_file,
    decrypt_private_key,
    derive_aes_key_from_hash,
    get_public_key_fingerprint,
    delete_user_key_files
)

class KeyManagementFrame(tk.Frame):
    def __init__(self, master, back_callback):
        super().__init__(master)
        self.master = master
        self.back_callback = back_callback
        self.pack()
        self.master.geometry("800x500")

        if not session.is_logged_in():
            messagebox.showerror("Error", "You must be logged in to access this feature.")
            self.back()
            return

        self.email = session.get_user()['email']

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)

        frame_mykey = tk.Frame(notebook)
        frame_pubkeys = tk.Frame(notebook)
        frame_findkey = tk.Frame(notebook)

        notebook.add(frame_mykey, text="My Key")
        notebook.add(frame_pubkeys, text="Public Keys")
        notebook.add(frame_findkey, text="Find Key")

        self.build_my_key_tab(frame_mykey)
        self.build_public_key_tab(frame_pubkeys)
        self.build_find_key_tab(frame_findkey)

    # =======================
    # TAB 1 - MY KEY
    # =======================
    def build_my_key_tab(self, container):
        tk.Label(container, text="My RSA Key", font=("Helvetica", 14)).pack(pady=10)

        key_info = get_user_key_info(self.email)
        if not key_info:
            tk.Label(container, text="No key found.").pack()
            return

        created_at, expire_at = key_info

        pub_path = f"data/keys/{self.email}/{self.email}_pub.pem"
        if not os.path.exists(pub_path):
            tk.Label(container, text="Public key file missing!").pack()
            return

        pub_key = load_key_from_file(pub_path, binary=True)
        fingerprint = get_public_key_fingerprint(pub_key)

        tk.Label(container, text=f"Fingerprint:\n{fingerprint}").pack(pady=10)

        status, color = calculate_key_expiration(created_at)
        tk.Label(container, text=f"Status: {status}", fg=color, font=("Helvetica", 12, "bold")).pack(pady=5)
        
        tk.Label(container, text=f"Created At: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(created_at))}").pack()
        tk.Label(container, text=f"Expires At: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expire_at))}").pack()

        tk.Button(container, text="Export Public Key to QR Code", command=self.export_public_key_qr).pack(pady=5)
        tk.Button(container, text="Download Public Key", command=self.download_public_key).pack(pady=5)
        tk.Button(container, text="Download Private Key", command=self.prompt_passphrase).pack(pady=5)
        tk.Button(container, text="Regenerate Key", command=self.confirm_regenerate).pack(pady=10)
        tk.Button(container, text="Back", command=self.back).pack(pady=15)

    def export_public_key_qr(self):
        pub_path = f"data/keys/{self.email}/{self.email}_pub.pem"

        if not os.path.exists(pub_path):
            messagebox.showerror("Error", "Public key file not found.")
            return

        pub_key_pem = load_key_from_file(pub_path, binary=True)

        # Get created_at
        key_info = get_user_key_info(self.email)
        if not key_info:
            messagebox.showerror("Error", "Cannot fetch key info.")
            return

        created_at, _ = key_info

        # Build payload
        qr_data = {
            "email": self.email,
            "created_at": created_at,
            "public_key": pub_key_pem.decode()
        }
        json_str = json.dumps(qr_data)
        qr_payload = base64.b64encode(json_str.encode()).decode()

        # Generate QR code
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=4,
            border=2
        )
        qr.add_data(qr_payload)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")

        # Resize
        qr_img = qr_img.resize((250, 250))

        qr_img_tk = ImageTk.PhotoImage(qr_img)

        # Show in Toplevel window
        win = tk.Toplevel(self)
        win.title("Public Key QR Code")
        win.geometry("400x400")

        tk.Label(win, text="Public Key QR Code:").pack(pady=10)
        tk.Label(win, image=qr_img_tk).pack()

        # Keep reference
        win.qr_img_tk = qr_img_tk

        def save_qr():
            path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
            if path:
                qr_img.save(path)
                messagebox.showinfo("Saved", f"QR code saved to:\n{path}")

        tk.Button(win, text="Save QR Image", command=save_qr).pack(pady=10)
        tk.Button(win, text="Close", command=win.destroy).pack(pady=5)

    def download_public_key(self):
        pub_path = f"data/keys/{self.email}/{self.email}_pub.pem"
        path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
        if path:
            with open(pub_path, "rb") as src, open(path, "wb") as dest:
                dest.write(src.read())
            messagebox.showinfo("Saved", f"Public key saved to:\n{path}")

    def prompt_passphrase(self):
        win = tk.Toplevel(self)
        win.title("Verify Passphrase")
        win.geometry("350x150")
        win.resizable(False, False)

        tk.Label(win, text="Enter your passphrase to download private key:").pack(pady=10)
        entry = tk.Entry(win, width=30, show="*")
        entry.pack()

        def confirm():
            user_input = entry.get()
            row = get_user_auth_info(self.email)
            if not row:
                messagebox.showerror("Error", "User info not found.")
                win.destroy()
                return

            stored_hash_b64, salt_b64, *_ = row
            input_hash_b64, _ = hash_passphrase(user_input, base64.b64decode(salt_b64))

            if input_hash_b64 != stored_hash_b64:
                messagebox.showerror("Error", "Incorrect passphrase.")
                win.destroy()
                return

            aes_key, _ = derive_aes_key_from_hash(stored_hash_b64, salt=None)

            priv_path = f"data/keys/{self.email}/{self.email}_priv.enc"
            with open(priv_path, "r") as f:
                enc_data = json.load(f)

            salt = base64.b64decode(enc_data["salt"])
            aes_key, _ = derive_aes_key_from_hash(stored_hash_b64, salt)
            decrypted = decrypt_private_key(enc_data, aes_key)

            if not decrypted:
                messagebox.showerror("Error", "Failed to decrypt private key.")
                win.destroy()
                return

            save_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
            if save_path:
                with open(save_path, "wb") as f:
                    f.write(decrypted)
                messagebox.showinfo("Saved", f"Private key saved to:\n{save_path}")
            win.destroy()

        tk.Button(win, text="Verify & Download", command=confirm).pack(pady=10)
        tk.Button(win, text="Cancel", command=win.destroy).pack()

    def confirm_regenerate(self):
        result = messagebox.askyesno(
            "Regenerate Key",
            "Are you sure you want to delete and recreate your RSA key?\nThis cannot be undone."
        )
        if result:
            delete_user_key_files(self.email)
            delete_user_key(self.email)

            row = get_user_auth_info(self.email)
            if not row:
                messagebox.showerror("Error", "Cannot retrieve passphrase hash.")
                return

            hash_b64 = row[0]

            self.pack_forget()
            self.destroy()
            KeyCreateFrame(
                master=self.master,
                email=self.email,
                passphrase_hash_b64=hash_b64,
                back_callback=self.back_callback
            )

    def back(self):
        self.pack_forget()
        self.destroy()
        self.back_callback()

    # =======================
    # TAB 2 - PUBLIC KEYS
    # =======================
    def build_public_key_tab(self, container):
        tk.Label(container, text="Public Keys Imported", font=("Helvetica", 14)).pack(pady=10)

        keys = load_other_public_keys(self.email)

        if not keys:
            tk.Label(container, text="No imported keys yet.").pack()
            return

        for key in keys:
            # Get created_at from DB
            row = get_user_key_info(key["email"])
            if row:
                created_at, _ = row
            else:
                created_at = 0

            status, color = calculate_key_expiration(created_at)
            fingerprint = get_public_key_fingerprint(load_key_from_file(key["pub_path"], binary=True))

            frame = tk.Frame(container, relief=tk.RIDGE, bd=1, padx=5, pady=5)
            frame.pack(fill="x", padx=5, pady=3)

            tk.Label(frame, text=f"Email: {key['email']}", font=("Helvetica", 10, "bold")).grid(row=0, column=0, sticky="w")
            tk.Label(frame, text=f"Status: {status}", fg=color).grid(row=0, column=1, sticky="w", padx=20)
            tk.Label(frame, text=f"Fingerprint: {fingerprint}").grid(row=1, column=0, columnspan=2, sticky="w")

    # =======================
    # TAB 3 - FIND KEY
    # =======================
    def build_find_key_tab(self, container):
        tk.Label(container, text="Find Public Key", font=("Helvetica", 14)).pack(pady=10)

        # Search by email
        tk.Label(container, text="Search by Email:").pack(pady=5)
        entry_email = tk.Entry(container, width=40)
        entry_email.pack()

        def search_email():
            target_email = entry_email.get().strip()
            if not target_email:
                messagebox.showerror("Error", "Please enter an email.")
                return
            if target_email == self.email:
                messagebox.showerror("Error", "You cannot search for your own key here.")
                return
            
            row = get_user_key_info(target_email)
            if not row:
                messagebox.showerror("Error", f"No key found for {target_email}.")
                return
            created_at, expire_at = row

            pub_path = f"data/keys/{target_email}/{target_email}_pub.pem"
            if not os.path.exists(pub_path):
                messagebox.showerror("Error", f"Public key file missing for {target_email}.")
                return

            with open(pub_path, "rb") as f:
                pub_key_pem = f.read()

            expire_in_days = (expire_at - time.time()) // (24 * 60 * 60)

            # QR payload
            qr_data = {
                "email": target_email,
                "created_at": created_at,
                "public_key": pub_key_pem.decode()
            }
            json_str = json.dumps(qr_data)
            qr_payload = base64.b64encode(json_str.encode()).decode()

            qr = qrcode.QRCode(box_size=4, border=2)
            qr.add_data(qr_payload)
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white")
            qr_img = qr_img.resize((250, 250))
            qr_img_tk = ImageTk.PhotoImage(qr_img)

            win = tk.Toplevel(self)
            win.title(f"Public Key for {target_email}")

            tk.Label(win, text=f"Email: {target_email}").pack()
            tk.Label(win, text=f"Created at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(created_at))}").pack()
            tk.Label(win, text=f"Expires in: {int(expire_in_days)} days").pack()
            
            tk.Label(win, image=qr_img_tk).pack()
            win.qr_img_tk = qr_img_tk

            def import_key():
                save_other_public_key(self.email, target_email, pub_key_pem)
                messagebox.showinfo("Success", f"Imported key for {target_email}.")
                self.refresh_tabs()
                win.destroy()

            tk.Button(win, text="Import Key", command=import_key).pack(pady=10)
            tk.Button(win, text="Close", command=win.destroy).pack()

        tk.Button(container, text="Search & Import", command=search_email).pack(pady=5)

        # Divider
        tk.Label(container, text="or", font=("Helvetica", 12, "italic")).pack(pady=10)

        # Import QR code
        tk.Button(container, text="Import from QR Code", command=self.import_qr_code).pack(pady=5)

    # Helper method to import QR code
    def import_qr_code(self):
        path = filedialog.askopenfilename(filetypes=[("PNG Files", "*.png")])
        if not path:
            return

        img = Image.open(path)
        decoded_objs = pyzbar.decode(img)

        if not decoded_objs:
            messagebox.showerror("Error", "Could not decode QR code.")
            return

        qr_data = decoded_objs[0].data
        try:
            json_str = base64.b64decode(qr_data).decode()
            obj = json.loads(json_str)

            other_email = obj["email"]
            public_key = obj["public_key"].encode()

            if other_email == self.email:
                messagebox.showerror("Error", "You cannot import your own key this way.")
                return

            save_other_public_key(self.email, other_email, public_key)
            messagebox.showinfo("Saved", f"Imported public key of {other_email}.")
            self.refresh_tabs()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse QR data:\n{e}")

    # Refresh the tabs to reflect changes
    def refresh_tabs(self):
        self.pack_forget()
        self.destroy()
        KeyManagementFrame(self.master, self.back_callback)

# Helper functions
def calculate_key_expiration(create_at):
    current_time = time.time()
    expire_at = create_at + (90 * 24 * 60 * 60)  # 90 days
    days_left = (expire_at - current_time) / (24 * 60 * 60)
    if current_time > expire_at:
        return "Expired", "red"
    elif days_left < 10:
        return f"Expiring in ({int(days_left)} days", "orange"
    else:
        return "Active", "green"
    
def save_other_public_key(my_email, other_email, public_key_pem):
    folder = f"data/keys/{my_email}/others"
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"{other_email}_pub.pem")

    if os.path.exists(path):
        messagebox.showwarning("Warning", f"Public key for {other_email} already exists. Overwriting.")

    with open(path, "wb") as f:
        f.write(public_key_pem)

def load_other_public_keys(my_email):
    folder = f"data/keys/{my_email}/others"
    os.makedirs(folder, exist_ok=True)

    keys = []
    for file in os.listdir(folder):
        if file.endswith("_pub.pem"):
            other_email = file.replace("_pub.pem", "")
            pub_path = os.path.join(folder, file)
            meta_path = os.path.join(folder, f"{other_email}_meta.json")

            if os.path.exists(meta_path):
                with open(meta_path, "r") as f:
                    meta = json.load(f)
                created_at = meta["created_at"]
            else:
                created_at = 0

            keys.append({
                "email": other_email,
                "pub_path": pub_path,
                "created_at": created_at,
            })
    return keys
