import tkinter as tk
from tkinter import messagebox
import time
from modules.core import session
from modules.utils.db_helper import get_user_key_info, get_user_auth_info, delete_user_key
from modules.utils.rsa_key_helper import delete_user_key_files
from gui.register_frame import RegisterFrame
from gui.login_frame import LoginFrame
from gui.account_update_frame import AccountUpdateFrame
from gui.key_create_frame import KeyCreateFrame
from gui.key_management_frame import KeyManagementFrame
from gui.encrypt_frame import EncryptFrame
from gui.decrypt_frame import DecryptFrame

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Computer Security Project 1")
        self.root.resizable(False, False)

        self.active_frame = None

        self.show_welcome_screen()

    def show_welcome_screen(self):
        self.clear_active_frame()

        if session.is_logged_in():
            email = session.get_user()['email']
            row = get_user_key_info(email)

            if not row:
                self.show_key_create(email)
                return

            created_at, expire_at = row
            if time.time() > expire_at:
                delete_user_key_files(email)
                delete_user_key(email)
                messagebox.showwarning("Key Expired", "Your RSA key has expired. Please create a new key.")
                self.show_key_create(email)
                return

        self.active_frame = tk.Frame(self.root)
        self.active_frame.pack()

        tk.Label(self.active_frame, text="Computer Security System", font=("Helvetica", 16, "bold")).pack(pady=20)

        if session.is_logged_in():
            self.root.geometry("600x500")
            user = session.get_user()
            tk.Label(self.active_frame, text=f"Welcome, {user['full_name']}!", font=("Helvetica", 14)).pack(pady=10)

            tk.Button(self.active_frame, text="Update Account", width=30, command=self.show_account_update).pack(pady=5)
            tk.Button(self.active_frame, text="Key Management", width=30, command=self.show_key_management).pack(pady=5)
            tk.Button(self.active_frame, text="Encrypt File", width=30, command=self.encrypt_file).pack(pady=5)
            tk.Button(self.active_frame, text="Decrypt File", width=30, command=self.decrypt_file).pack(pady=5)
            tk.Button(self.active_frame, text="Digital Signature", width=30, command=self.sign_file).pack(pady=5)
            tk.Button(self.active_frame, text="Verify Signature", width=30, command=self.verify_signature).pack(pady=5)
            tk.Button(self.active_frame, text="Admin Dashboard", width=30, command=self.open_admin_dashboard).pack(pady=5)
            tk.Button(self.active_frame, text="Logout", width=30, command=self.logout).pack(pady=20)
        else:
            self.root.geometry("400x300")
            tk.Button(self.active_frame, text="Register", width=30, command=self.show_register).pack(pady=10)
            tk.Button(self.active_frame, text="Login", width=30, command=self.show_login).pack(pady=10)
            tk.Button(self.active_frame, text="Account Recovery", width=30, command=self.account_recovery).pack(pady=10)
            tk.Button(self.active_frame, text="Exit", width=30, command=self.root.quit).pack(pady=20)

    def clear_active_frame(self):
        if self.active_frame:
            self.active_frame.pack_forget()
            self.active_frame.destroy()
            self.active_frame = None

    def show_register(self):
        self.clear_active_frame()
        self.active_frame = RegisterFrame(self.root, self.show_welcome_screen)

    def show_login(self):
        self.clear_active_frame()
        self.active_frame = LoginFrame(self.root, self.show_welcome_screen)

    def show_account_update(self):
        self.clear_active_frame()
        self.active_frame = AccountUpdateFrame(self.root, self.show_welcome_screen)

    def show_key_management(self):
        self.clear_active_frame()
        self.active_frame = KeyManagementFrame(self.root, self.show_welcome_screen)

    def encrypt_file(self):
        self.clear_active_frame()
        self.active_frame = EncryptFrame(self.root, self.show_welcome_screen)

    def decrypt_file(self):
        self.clear_active_frame()
        self.active_frame = DecryptFrame(self.root, self.show_welcome_screen)

    def sign_file(self):
        messagebox.showinfo("Info", "Sign functionality here.")

    def verify_signature(self):
        messagebox.showinfo("Info", "Verify functionality here.")

    def open_admin_dashboard(self):
        messagebox.showinfo("Info", "Admin Dashboard here.")

    def logout(self):
        user = session.get_user()
        session.logout_user()
        messagebox.showinfo("Logout", f"User '{user['email']}' logged out.")
        self.show_welcome_screen()

    def account_recovery(self):
        messagebox.showinfo("Info", "Account recovery window.")

    def show_key_create(self, email):
        # Lấy passphrase_hash từ DB
        row = get_user_auth_info(email)
        if row:
            passphrase_hash_b64 = row[0]
        else:
            messagebox.showerror("Error", f"Cannot fetch passphrase hash for {email}.")
            self.show_welcome_screen()
            return

        self.clear_active_frame()
        self.active_frame = KeyCreateFrame(
            master=self.root,
            email=email,
            passphrase_hash_b64=passphrase_hash_b64,
            back_callback=self.logout,
            front_callback=self.show_welcome_screen
        )
