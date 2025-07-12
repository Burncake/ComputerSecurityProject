import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
from modules.utils.signature_helper import verify_file_signature, get_signature_details
from modules.utils import logger

class VerifyFrame(tk.Frame):
    def __init__(self, master, back_callback):
        super().__init__(master)
        self.back_callback = back_callback
        self.master.geometry("500x400")
        self.pack(padx=20, pady=20)

        # Title
        tk.Label(self, text="Verify Digital Signature", font=("Helvetica", 16, "bold")).pack(pady=10)

        # File selection
        file_frame = tk.Frame(self)
        file_frame.pack(fill="x", pady=10)
        
        tk.Label(file_frame, text="Select original file:", font=("Helvetica", 12)).pack(anchor="w")
        
        select_frame = tk.Frame(file_frame)
        select_frame.pack(fill="x", pady=5)
        
        self.file_path = tk.StringVar()
        tk.Entry(select_frame, textvariable=self.file_path, state="readonly", width=50).pack(side="left", fill="x", expand=True)
        tk.Button(select_frame, text="Browse...", command=self.browse_file).pack(side="right", padx=(5, 0))

        # Signature file selection
        sig_frame = tk.Frame(self)
        sig_frame.pack(fill="x", pady=10)
        
        tk.Label(sig_frame, text="Select signature file (.sig):", font=("Helvetica", 12)).pack(anchor="w")
        
        sig_select_frame = tk.Frame(sig_frame)
        sig_select_frame.pack(fill="x", pady=5)
        
        self.sig_path = tk.StringVar()
        tk.Entry(sig_select_frame, textvariable=self.sig_path, state="readonly", width=50).pack(side="left", fill="x", expand=True)
        tk.Button(sig_select_frame, text="Browse...", command=self.browse_signature).pack(side="right", padx=(5, 0))

        # Auto-detect button
        tk.Button(self, text="Auto-detect signature file", 
                 command=self.auto_detect_signature).pack(pady=5)

        # Buttons
        button_frame = tk.Frame(self)
        button_frame.pack(fill="x", pady=20)
        
        tk.Button(button_frame, text="Verify Signature", command=self.verify_signature,
                 bg="#2196F3", fg="white", font=("Helvetica", 12, "bold")).pack(pady=5)
        tk.Button(button_frame, text="Back", command=self.back_callback).pack(pady=5)

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select original file to verify",
            filetypes=[("All Files", "*.*")]
        )
        if file_path:
            self.file_path.set(file_path)
            # Auto-suggest signature file
            sig_path = file_path + ".sig"
            if os.path.exists(sig_path):
                self.sig_path.set(sig_path)

    def browse_signature(self):
        sig_path = filedialog.askopenfilename(
            title="Select signature file",
            filetypes=[("Signature Files", "*.sig"), ("All Files", "*.*")]
        )
        if sig_path:
            self.sig_path.set(sig_path)

    def auto_detect_signature(self):
        file_path = self.file_path.get()
        if not file_path:
            messagebox.showwarning("Warning", "Please select the original file first.")
            return

        sig_path = file_path + ".sig"
        if os.path.exists(sig_path):
            self.sig_path.set(sig_path)
            messagebox.showinfo("Found", f"Signature file found:\n{os.path.basename(sig_path)}")
        else:
            messagebox.showwarning("Not Found", "No signature file found with the expected name.")

    def verify_signature(self):
        file_path = self.file_path.get()
        sig_path = self.sig_path.get()

        # Validation
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file to verify.")
            return

        if not sig_path or not os.path.exists(sig_path):
            messagebox.showerror("Error", "Please select a valid signature file.")
            return

        try:
            # Get signature details first
            sig_details = get_signature_details(sig_path)
            if not sig_details:
                messagebox.showerror("Error", "Invalid signature file format.")
                return

            # Verify the signature
            is_valid, message = verify_file_signature(file_path, sig_path)
            
            # Show results
            self.show_verification_result(is_valid, message, sig_details, file_path)
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during verification:\n{str(e)}")

    def show_verification_result(self, is_valid, message, sig_details, file_path):
        """Show verification results in a detailed window"""
        result_win = tk.Toplevel(self)
        result_win.title("Signature Verification Result")
        result_win.geometry("700x600")
        result_win.resizable(False, False)

        # Result header
        if is_valid:
            header_text = "✓ SIGNATURE VALID"
            header_color = "green"
            bg_color = "#E8F5E8"
        else:
            header_text = "✗ SIGNATURE INVALID"
            header_color = "red"
            bg_color = "#FFE8E8"

        header_frame = tk.Frame(result_win, bg=bg_color)
        header_frame.pack(fill="x", pady=5)
        
        tk.Label(header_frame, text=header_text, font=("Helvetica", 18, "bold"), 
                fg=header_color, bg=bg_color).pack(pady=10)
        tk.Label(header_frame, text=message, font=("Helvetica", 12), 
                bg=bg_color).pack(pady=5)

        # Create notebook for detailed info
        notebook = ttk.Notebook(result_win)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Signature Info tab
        info_frame = tk.Frame(notebook)
        notebook.add(info_frame, text="Signature Information")

        info_text = f"""Signed File: {sig_details.get('file_name', 'Unknown')}
Original File Size: {sig_details.get('file_size', 'Unknown'):,} bytes
Signer: {sig_details.get('signer_email', 'Unknown')}
Signed On: {sig_details.get('timestamp', 'Unknown')}
Algorithm: {sig_details.get('algorithm', 'Unknown')}
Key Size: {sig_details.get('key_size', 'Unknown')} bits

Verification Message: {message}"""

        tk.Label(info_frame, text=info_text, justify="left", 
                font=("Helvetica", 11)).pack(anchor="w", padx=10, pady=10)

        # File Comparison tab
        compare_frame = tk.Frame(notebook)
        notebook.add(compare_frame, text="File Comparison")

        current_size = os.path.getsize(file_path)
        original_size = sig_details.get('file_size', 0)
        
        size_match = "✓ Match" if current_size == original_size else "✗ Mismatch"
        size_color = "green" if current_size == original_size else "red"

        compare_text = f"""File Size Comparison:
Original (at signing): {original_size:,} bytes
Current: {current_size:,} bytes
Status: {size_match}

File Path Comparison:
Original: {sig_details.get('file_path', 'Unknown')}
Current: {os.path.abspath(file_path)}

Hash Verification: {"✓ Valid" if is_valid else "✗ Invalid"}"""

        tk.Label(compare_frame, text=compare_text, justify="left", 
                font=("Helvetica", 11)).pack(anchor="w", padx=10, pady=10)

        # Technical Details tab
        tech_frame = tk.Frame(notebook)
        notebook.add(tech_frame, text="Technical Details")

        tech_text = tk.Text(tech_frame, wrap="word", height=15, width=80)
        tech_scrollbar = tk.Scrollbar(tech_frame, orient="vertical", command=tech_text.yview)
        tech_text.configure(yscrollcommand=tech_scrollbar.set)
        
        tech_text.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        tech_scrollbar.pack(side="right", fill="y")

        tech_details = f"""SHA-256 Hash (from signature):
{sig_details.get('sha256_hash', 'Unknown')}

Digital Signature (Base64):
{sig_details.get('signature', 'Unknown')}

Unix Timestamp: {sig_details.get('unix_timestamp', 'Unknown')}
Full Original Path: {sig_details.get('file_path', 'Unknown')}"""

        tech_text.insert("1.0", tech_details)
        tech_text.config(state="disabled")

        # Buttons
        button_frame = tk.Frame(result_win)
        button_frame.pack(fill="x", pady=10)

        tk.Button(button_frame, text="Close", 
                 command=result_win.destroy).pack(side="right", padx=5)

        # Log the verification
        logger.log_info(f"Signature verification: {message} - File: {os.path.basename(file_path)}")