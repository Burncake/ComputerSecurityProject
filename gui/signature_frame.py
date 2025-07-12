
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
from modules.core import session
from modules.utils.signature_helper import sign_file_with_user, get_signature_details
from modules.utils import logger

class SignFrame(tk.Frame):
    def __init__(self, master, back_callback):
        super().__init__(master)
        self.back_callback = back_callback
        self.master.geometry("500x400")
        self.pack(padx=20, pady=20)

        if not session.is_logged_in():
            messagebox.showerror("Error", "You must be logged in to sign files.")
            return

        self.email = session.get_user()['email']

        # Title
        tk.Label(self, text="Digital File Signature", font=("Helvetica", 16, "bold")).pack(pady=10)

        # File selection
        file_frame = tk.Frame(self)
        file_frame.pack(fill="x", pady=10)
        
        tk.Label(file_frame, text="Select file to sign:", font=("Helvetica", 12)).pack(anchor="w")
        
        select_frame = tk.Frame(file_frame)
        select_frame.pack(fill="x", pady=5)
        
        self.file_path = tk.StringVar()
        tk.Entry(select_frame, textvariable=self.file_path, state="readonly", width=50).pack(side="left", fill="x", expand=True)
        tk.Button(select_frame, text="Browse...", command=self.browse_file).pack(side="right", padx=(5, 0))

        # Passphrase verification
        pass_frame = tk.Frame(self)
        pass_frame.pack(fill="x", pady=10)
        
        tk.Label(pass_frame, text="Enter your passphrase to sign:", font=("Helvetica", 12)).pack(anchor="w")
        self.passphrase_entry = tk.Entry(pass_frame, show="*", width=50)
        self.passphrase_entry.pack(pady=5)

        # Show passphrase checkbox
        self.show_pass_var = tk.BooleanVar()
        tk.Checkbutton(pass_frame, text="Show passphrase", 
                      variable=self.show_pass_var, 
                      command=self.toggle_passphrase).pack(anchor="w")

        # Buttons
        button_frame = tk.Frame(self)
        button_frame.pack(fill="x", pady=20)
        
        tk.Button(button_frame, text="Sign File", command=self.sign_file, 
                 bg="#4CAF50", fg="white", font=("Helvetica", 12, "bold")).pack(pady=5)
        tk.Button(button_frame, text="Back", command=self.back_callback).pack(pady=5)

        # Results frame
        self.results_frame = tk.Frame(self)

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select file to sign",
            filetypes=[("All Files", "*.*")]
        )
        if file_path:
            self.file_path.set(file_path)

    def toggle_passphrase(self):
        if self.show_pass_var.get():
            self.passphrase_entry.config(show="")
        else:
            self.passphrase_entry.config(show="*")

    def sign_file(self):
        file_path = self.file_path.get()
        passphrase = self.passphrase_entry.get()

        # Validation
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file to sign.")
            return

        if not passphrase:
            messagebox.showerror("Error", "Please enter your passphrase.")
            return

        try:
            # Sign the file
            success, sig_file_path, result = sign_file_with_user(file_path, self.email, passphrase)
            
            if success:
                # Clear passphrase
                self.passphrase_entry.delete(0, tk.END)
                
                # Show success message and signature details
                self.show_signature_success(sig_file_path, result)
                
            else:
                messagebox.showerror("Signing Failed", f"Failed to sign file:\n{result}")
                
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while signing:\n{str(e)}")

    def show_signature_success(self, sig_file_path, signature_data):
        """Show signature success dialog with details"""
        success_win = tk.Toplevel(self)
        success_win.title("File Signed Successfully")
        success_win.geometry("600x500")
        success_win.resizable(False, False)

        # Title
        tk.Label(success_win, text="✓ File Signed Successfully", 
                font=("Helvetica", 16, "bold"), fg="green").pack(pady=10)

        # Create notebook for tabs
        notebook = ttk.Notebook(success_win)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Summary tab
        summary_frame = tk.Frame(notebook)
        notebook.add(summary_frame, text="Summary")

        tk.Label(summary_frame, text="Signature Details:", font=("Helvetica", 12, "bold")).pack(anchor="w", pady=5)
        
        details_text = f"""File: {signature_data['file_name']}
Size: {signature_data['file_size']:,} bytes
Signer: {signature_data['signer_email']}
Timestamp: {signature_data['timestamp']}
Algorithm: {signature_data['algorithm']}
Key Size: {signature_data['key_size']} bits
Signature File: {os.path.basename(sig_file_path)}"""

        tk.Label(summary_frame, text=details_text, justify="left", 
                font=("Helvetica", 10)).pack(anchor="w", padx=10, pady=5)

        # Technical Details tab
        tech_frame = tk.Frame(notebook)
        notebook.add(tech_frame, text="Technical Details")

        tech_text = tk.Text(tech_frame, wrap="word", height=20, width=70)
        tech_text.pack(fill="both", expand=True, padx=10, pady=10)

        tech_details = f"""SHA-256 Hash: {signature_data['sha256_hash']}

Digital Signature (Base64):
{signature_data['signature']}

Full File Path: {signature_data['file_path']}
Unix Timestamp: {signature_data['unix_timestamp']}"""

        tech_text.insert("1.0", tech_details)
        tech_text.config(state="disabled")

        # Buttons
        button_frame = tk.Frame(success_win)
        button_frame.pack(fill="x", pady=10)

        def open_sig_location():
            import subprocess
            import platform
            
            sig_dir = os.path.dirname(sig_file_path)
            if platform.system() == "Linux":
                subprocess.run(["xdg-open", sig_dir])
            elif platform.system() == "Darwin":  # macOS
                subprocess.run(["open", sig_dir])
            elif platform.system() == "Windows":
                subprocess.run(["explorer", sig_dir])

        tk.Button(button_frame, text="Open Signature Location", 
                 command=open_sig_location).pack(side="left", padx=5)
        tk.Button(button_frame, text="Close", 
                 command=success_win.destroy).pack(side="right", padx=5)

        logger.log_info(f"User '{self.email}' successfully signed file '{signature_data['file_name']}'")