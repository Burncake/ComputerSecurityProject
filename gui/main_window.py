import tkinter as tk
from tkinter import messagebox

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Computer Security Project 1")

        # Window size
        self.root.geometry("400x500")
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

    def open_login(self):
        messagebox.showinfo("Info", "Open Login Window")

    def encrypt_file(self):
        messagebox.showinfo("Info", "Encrypt File Window")

    def decrypt_file(self):
        messagebox.showinfo("Info", "Decrypt File Window")

    def sign_file(self):
        messagebox.showinfo("Info", "Sign File Window")

    def verify_signature(self):
        messagebox.showinfo("Info", "Verify Signature Window")

    def open_admin_dashboard(self):
        messagebox.showinfo("Info", "Admin Dashboard Window")

if __name__ == "__main__":
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()
