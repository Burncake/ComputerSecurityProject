import tkinter as tk
from tkinter import messagebox

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Computer Security Project 1")
        self.root.resizable(False, False)

        # Title label
        title = tk.Label(root, text="Computer Security System", font=("Helvetica", 16, "bold"))
        title.pack(pady=20)

        # Buttons for main features
        btn_register = tk.Button(root, text="Register", width=30, command=self.open_register)
        btn_register.pack(pady=10)

        btn_login = tk.Button(root, text="Login", width=30, command=self.open_login)
        btn_login.pack(pady=10)

        btn_encrypt = tk.Button(root, text="Encrypt File", width=30, command=self.encrypt_file)
        btn_encrypt.pack(pady=10)

        btn_decrypt = tk.Button(root, text="Decrypt File", width=30, command=self.decrypt_file)
        btn_decrypt.pack(pady=10)

        btn_sign = tk.Button(root, text="Digital Signature", width=30, command=self.sign_file)
        btn_sign.pack(pady=10)

        btn_verify = tk.Button(root, text="Verify Signature", width=30, command=self.verify_signature)
        btn_verify.pack(pady=10)

        btn_admin = tk.Button(root, text="Admin Dashboard", width=30, command=self.open_admin_dashboard)
        btn_admin.pack(pady=10)

        btn_exit = tk.Button(root, text="Exit", width=30, command=self.root.quit)
        btn_exit.pack(pady=20)

    # Placeholder methods
    def open_register(self):
        from register_window import RegisterWindow
        RegisterWindow(self.root)

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
        self.clear_active_frame()
        self.active_frame = SignFrame(self.root, self.show_welcome_screen)

    def verify_signature(self):
        self.clear_active_frame()
        self.active_frame = VerifyFrame(self.root, self.show_welcome_screen)

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