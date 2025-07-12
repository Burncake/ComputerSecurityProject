import tkinter as tk
from tkinter import filedialog, messagebox
import os
from modules.utils import logger
from modules.core import session
from modules.utils.file_crypto_helper import encrypt_file_for_user
from modules.utils.db_helper import get_user_key_list

class EncryptFrame(tk.Frame):
    def __init__(self, master, back_callback):
        super().__init__(master)
        self.back_callback = back_callback
        self.pack(padx=20, pady=20)

        if not session.is_logged_in():
            messagebox.showerror("Error", "You must be logged in to encrypt files.")
            return

        self.sender = session.get_user()['email']

        tk.Label(self, text="Encrypt File for Another User", font=("Helvetica", 14)).pack(pady=10)

        # File chooser
        self.filepath = tk.StringVar()
        tk.Button(self, text="Choose File…", command=self.choose_file).pack(fill="x")
        tk.Entry(self, textvariable=self.filepath, state="readonly").pack(fill="x", pady=5)

        # Receiver selection
        tk.Label(self, text="Select Recipient:").pack(pady=5)
        # load all users who have keys
        users = [row[0] for row in get_user_key_list()]  # each row is (email,)
        self.recv_var = tk.StringVar(value=(users[0] if users else ""))
        tk.OptionMenu(self, self.recv_var, *users).pack(fill="x")

        # Mode radio
        tk.Label(self, text="Output Mode:").pack(pady=5)
        self.mode = tk.StringVar(value="combined")
        tk.Radiobutton(self, text="Single .enc file", variable=self.mode, value="combined").pack(anchor="w")
        tk.Radiobutton(self, text="Separate .enc + .key files", variable=self.mode, value="separate").pack(anchor="w")

        # Buttons
        tk.Button(self, text="Encrypt & Save", command=self.do_encrypt).pack(pady=15)
        tk.Button(self, text="Back", command=self.back_callback).pack()

    def choose_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.filepath.set(path)

    def do_encrypt(self):
        inpath = self.filepath.get()
        recv = self.recv_var.get()
        mode = self.mode.get()

        if not inpath or not os.path.isfile(inpath):
            messagebox.showerror("Error", "Please choose a valid file.")
            return
        if not recv:
            messagebox.showerror("Error", "Please select a recipient.")
            return

        # load receiver public key PEM
        pub_path = f"data/keys/{recv}/{recv}_pub.pem"
        if not os.path.exists(pub_path):
            messagebox.showerror("Error", f"No public key found for {recv}.")
            return
        with open(pub_path, "rb") as f:
            receiver_pub = f.read()

        # choose output
        if mode == "combined":
            default_name = os.path.basename(inpath) + ".enc"
            out = filedialog.asksaveasfilename(
                defaultextension=".enc",
                initialfile=default_name,
                filetypes=[("ENC files", "*.enc")]
            )
            if not out:
                return
            try:
                encrypt_file_for_user(self.sender, receiver_pub, inpath, out, mode="combined")
                logger.log_info(f"User '{self.sender}' encrypted file '{os.path.basename(inpath)}' for '{recv}' in combined mode.")
                messagebox.showinfo("Success", f"Encrypted file saved to:\n{out}")
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed:\n{e}")
        else:
            outdir = filedialog.askdirectory()
            if not outdir:
                return
            try:
                enc_path, key_path = encrypt_file_for_user(
                    self.sender, receiver_pub, inpath, outdir, mode="separate"
                )
                logger.log_info(f"User '{self.sender}' encrypted file '{os.path.basename(inpath)}' for '{recv}' in separate mode.")
                messagebox.showinfo("Success", f"Ciphertext saved to:\n{enc_path}\nSession key saved to:\n{key_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed:\n{e}")

        self.back_callback()
