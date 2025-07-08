import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from PIL import ImageTk
from datetime import datetime
from modules.core import session
from modules.key_mgmt.rsa_helper import (
    generate_rsa_keypair,
    get_user_key_info,
    save_key_to_file,
    get_all_public_keys,
    add_external_public_key,
    decrypt_private_key
)
from modules.utils.qr_helper import (
    create_public_key_qr,
    save_qr_image,
    get_qr_image_as_tk,
    manual_qr_input_dialog,
    get_qr_data_as_text
)
from modules.utils import logger
import base64

class KeyManagementFrame(tk.Frame):
    def __init__(self, master, back_callback):
        super().__init__(master)
        self.back_callback = back_callback
        self.master.geometry("800x600")
        self.pack()

        self.email = session.get_user()['email']

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        self.tab_my_keys = ttk.Frame(self.notebook)
        self.tab_public_keys = ttk.Frame(self.notebook)
        self.tab_qr_input = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_my_keys, text="My Keys")
        self.notebook.add(self.tab_public_keys, text="Public Keys")
        self.notebook.add(self.tab_qr_input, text="QR Input")

        self.setup_my_keys_tab()
        self.setup_public_keys_tab()
        self.setup_qr_input_tab()

        tk.Button(self, text="Back", command=self.back).pack(pady=10)

    def setup_my_keys_tab(self):
        tk.Label(self.tab_my_keys, text="RSA Key Management", font=("Helvetica", 14, "bold")).pack(pady=10)

        self.key_info_frame = tk.Frame(self.tab_my_keys)
        self.key_info_frame.pack(pady=10)

        tk.Button(self.tab_my_keys, text="Generate New RSA Key Pair", command=self.generate_keys).pack(pady=5)
        tk.Button(self.tab_my_keys, text="Export Public Key", command=self.export_public_key).pack(pady=5)
        tk.Button(self.tab_my_keys, text="Export Private Key", command=self.export_private_key).pack(pady=5)
        tk.Button(self.tab_my_keys, text="Generate QR Code", command=self.generate_qr_code).pack(pady=5)

        self.update_key_info()

    def setup_public_keys_tab(self):
        tk.Label(self.tab_public_keys, text="Public Keys Directory", font=("Helvetica", 14, "bold")).pack(pady=10)

        self.keys_frame = tk.Frame(self.tab_public_keys)
        self.keys_frame.pack(fill='both', expand=True, padx=10, pady=10)

        columns = ('Email', 'Created Date', 'Expire Date', 'Status')
        self.keys_tree = ttk.Treeview(self.keys_frame, columns=columns, show='headings', height=15)

        for col in columns:
            self.keys_tree.heading(col, text=col)
            self.keys_tree.column(col, width=150)

        scrollbar = ttk.Scrollbar(self.keys_frame, orient='vertical', command=self.keys_tree.yview)
        self.keys_tree.configure(yscrollcommand=scrollbar.set)

        self.keys_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        tk.Button(self.tab_public_keys, text="Refresh", command=self.refresh_public_keys).pack(pady=5)

        self.refresh_public_keys()

    def setup_qr_input_tab(self):
        tk.Label(self.tab_qr_input, text="QR Code Input", font=("Helvetica", 14, "bold")).pack(pady=10)
        
        info_frame = tk.Frame(self.tab_qr_input)
        info_frame.pack(pady=10)
        
        tk.Label(info_frame, text="QR code scanning is not available in this version.", fg="orange").pack()
        tk.Label(info_frame, text="You can manually input QR code data or copy QR data to share.", fg="gray").pack()

        button_frame = tk.Frame(self.tab_qr_input)
        button_frame.pack(pady=20)
        
        tk.Button(button_frame, text="Manual QR Input", command=self.manual_qr_input, width=20).pack(pady=5)
        tk.Button(button_frame, text="Show My QR Data", command=self.show_my_qr_data, width=20).pack(pady=5)

        self.qr_info_frame = tk.Frame(self.tab_qr_input)
        self.qr_info_frame.pack(pady=20, fill='both', expand=True)

    def update_key_info(self):
        for widget in self.key_info_frame.winfo_children():
            widget.destroy()

        key_info = get_user_key_info(self.email)
        if key_info:
            public_key_b64, created_date, expire_date, is_active = key_info

            tk.Label(self.key_info_frame, text="Current Key Status:", font=("Helvetica", 12, "bold")).pack()
            tk.Label(self.key_info_frame, text=f"Created: {created_date}").pack()
            tk.Label(self.key_info_frame, text=f"Expires: {expire_date}").pack()

            expire_dt = datetime.strptime(expire_date, '%Y-%m-%d %H:%M:%S')
            now = datetime.now()
            days_left = (expire_dt - now).days

            if days_left > 0:
                status_text = f"Active ({days_left} days remaining)"
                status_color = "green" if days_left > 30 else "orange"
            else:
                status_text = "Expired"
                status_color = "red"

            status_label = tk.Label(self.key_info_frame, text=f"Status: {status_text}", fg=status_color)
            status_label.pack()
        else:
            tk.Label(self.key_info_frame, text="No RSA key pair found. Generate one first.", fg="red").pack()

    def generate_keys(self):
        passphrase_window = tk.Toplevel(self)
        passphrase_window.title("Enter Passphrase")
        passphrase_window.geometry("300x150")
        passphrase_window.resizable(False, False)

        tk.Label(passphrase_window, text="Enter your passphrase:").pack(pady=10)
        passphrase_entry = tk.Entry(passphrase_window, show="*", width=30)
        passphrase_entry.pack(pady=5)

        def confirm_generate():
            passphrase = passphrase_entry.get()
            if not passphrase:
                messagebox.showerror("Error", "Please enter your passphrase.")
                return

            try:
                public_key_b64, created_date, expire_date = generate_rsa_keypair(self.email, passphrase)
                logger.log_info(f"RSA key pair generated for user '{self.email}'")
                messagebox.showinfo("Success", "RSA key pair generated successfully!")
                passphrase_window.destroy()
                self.update_key_info()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate keys: {str(e)}")

        tk.Button(passphrase_window, text="Generate", command=confirm_generate).pack(pady=10)
        tk.Button(passphrase_window, text="Cancel", command=passphrase_window.destroy).pack()

    def export_public_key(self):
        key_info = get_user_key_info(self.email)
        if not key_info:
            messagebox.showerror("Error", "No key pair found. Generate one first.")
            return

        public_key_b64 = key_info[0]
        public_key_pem = base64.b64decode(public_key_b64).decode()

        filename = f"{self.email}_public_key.pem"
        filepath = save_key_to_file(public_key_pem, filename)
        logger.log_info(f"Public key exported for user '{self.email}' to {filepath}")
        messagebox.showinfo("Success", f"Public key exported to {filepath}")

    def export_private_key(self):
        key_info = get_user_key_info(self.email)
        if not key_info:
            messagebox.showerror("Error", "No key pair found. Generate one first.")
            return

        passphrase_window = tk.Toplevel(self)
        passphrase_window.title("Enter Passphrase")
        passphrase_window.geometry("300x150")
        passphrase_window.resizable(False, False)

        tk.Label(passphrase_window, text="Enter your passphrase:").pack(pady=10)
        passphrase_entry = tk.Entry(passphrase_window, show="*", width=30)
        passphrase_entry.pack(pady=5)

        def confirm_export():
            passphrase = passphrase_entry.get()
            if not passphrase:
                messagebox.showerror("Error", "Please enter your passphrase.")
                return

            try:
                private_key_pem = decrypt_private_key(self.email, passphrase)
                if private_key_pem:
                    filename = f"{self.email}_private_key.pem"
                    filepath = save_key_to_file(private_key_pem.decode(), filename)
                    logger.log_info(f"Private key exported for user '{self.email}' to {filepath}")
                    messagebox.showinfo("Success", f"Private key exported to {filepath}")
                    passphrase_window.destroy()
                else:
                    messagebox.showerror("Error", "Failed to decrypt private key. Check your passphrase.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export private key: {str(e)}")

        tk.Button(passphrase_window, text="Export", command=confirm_export).pack(pady=10)
        tk.Button(passphrase_window, text="Cancel", command=passphrase_window.destroy).pack()

    def generate_qr_code(self):
        key_info = get_user_key_info(self.email)
        if not key_info:
            messagebox.showerror("Error", "No key pair found. Generate one first.")
            return

        public_key_b64, created_date, _, _ = key_info

        qr_image = create_public_key_qr(self.email, created_date, public_key_b64)
        filepath = save_qr_image(qr_image, self.email)

        logger.log_info(f"QR code generated for user '{self.email}' public key")
        messagebox.showinfo("Success", f"QR code saved to {filepath}")

        qr_window = tk.Toplevel(self)
        qr_window.title("Public Key QR Code")
        qr_window.geometry("400x500")

        tk.Label(qr_window, text="Your Public Key QR Code", font=("Helvetica", 12, "bold")).pack(pady=10)

        tk_image = ImageTk.PhotoImage(get_qr_image_as_tk(qr_image))
        tk.Label(qr_window, image=tk_image).pack(pady=10)
        qr_window.image = tk_image

        tk.Label(qr_window, text=f"Saved to: {filepath}", font=("Helvetica", 10)).pack(pady=5)
        tk.Label(qr_window, text="Share this QR code to distribute your public key", font=("Helvetica", 9), fg="gray").pack(pady=5)

    def refresh_public_keys(self):
        for item in self.keys_tree.get_children():
            self.keys_tree.delete(item)

        keys = get_all_public_keys()
        for email, public_key, created_date, expire_date, is_active in keys:
            expire_dt = datetime.strptime(expire_date, '%Y-%m-%d %H:%M:%S')
            now = datetime.now()
            
            if expire_dt < now:
                status = "Expired"
            elif is_active:
                status = "Active (Own)"
            else:
                status = "External"

            self.keys_tree.insert('', 'end', values=(email, created_date, expire_date, status))

    def manual_qr_input(self):
        result, message = manual_qr_input_dialog(self)

        for widget in self.qr_info_frame.winfo_children():
            widget.destroy()

        if result:
            tk.Label(self.qr_info_frame, text="QR Code Information:", font=("Helvetica", 12, "bold")).pack()
            tk.Label(self.qr_info_frame, text=f"Email: {result['email']}").pack()
            tk.Label(self.qr_info_frame, text=f"Created Date: {result['created_date']}").pack()

            def add_key():
                success = add_external_public_key(result['email'], result['public_key'], result['created_date'])
                if success:
                    logger.log_info(f"External public key added for '{result['email']}'")
                    messagebox.showinfo("Success", "Public key added successfully!")
                    self.refresh_public_keys()
                else:
                    messagebox.showwarning("Warning", "This public key already exists.")

            tk.Button(self.qr_info_frame, text="Add to Public Keys", command=add_key).pack(pady=10)
        else:
            tk.Label(self.qr_info_frame, text=f"Status: {message}", fg="red").pack()

    def show_my_qr_data(self):
        key_info = get_user_key_info(self.email)
        if not key_info:
            messagebox.showerror("Error", "No key pair found. Generate one first.")
            return

        public_key_b64, created_date, _, _ = key_info
        qr_data_text = get_qr_data_as_text(self.email, created_date, public_key_b64)

        data_window = tk.Toplevel(self)
        data_window.title("My QR Code Data")
        data_window.geometry("600x400")

        tk.Label(data_window, text="QR Code Data (JSON Format)", font=("Helvetica", 12, "bold")).pack(pady=10)
        tk.Label(data_window, text="Copy this data to share your public key:", font=("Helvetica", 10)).pack(pady=5)

        text_frame = tk.Frame(data_window)
        text_frame.pack(fill='both', expand=True, padx=10, pady=10)

        text_area = tk.Text(text_frame, wrap='word', font=("Courier", 10))
        text_area.insert('1.0', qr_data_text)
        text_area.config(state='disabled')

        scrollbar = tk.Scrollbar(text_frame, orient='vertical', command=text_area.yview)
        text_area.configure(yscrollcommand=scrollbar.set)

        text_area.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        def copy_to_clipboard():
            data_window.clipboard_clear()
            data_window.clipboard_append(qr_data_text)
            messagebox.showinfo("Copied", "QR code data copied to clipboard!")

        tk.Button(data_window, text="Copy to Clipboard", command=copy_to_clipboard).pack(pady=10)

    def back(self):
        self.pack_forget()
        self.destroy()
        self.back_callback()