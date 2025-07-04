import tkinter as tk
from tkinter import messagebox
import re
import sys
import os

# Add the project root to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.auth.database import DatabaseManager
from modules.key_mgmt.rsa_manager import RSAKeyManager

class RegisterWindow:
    def __init__(self, master):
        self.db_manager = DatabaseManager()
        self.rsa_manager = RSAKeyManager()
        
        self.top = tk.Toplevel(master)
        self.top.title("Register New User")
        self.top.geometry("400x500")
        self.top.resizable(False, False)

        tk.Label(self.top, text="Username:").pack(pady=5)
        self.entry_username = tk.Entry(self.top, width=40)
        self.entry_username.pack(pady=5)

        tk.Label(self.top, text="Email:").pack(pady=5)
        self.entry_email = tk.Entry(self.top, width=40)
        self.entry_email.pack(pady=5)

        tk.Label(self.top, text="Passphrase:").pack(pady=5)
        self.entry_passphrase = tk.Entry(self.top, width=40, show="*")
        self.entry_passphrase.pack(pady=5)

        tk.Label(self.top, text="Confirm Passphrase:").pack(pady=5)
        self.entry_confirm = tk.Entry(self.top, width=40, show="*")
        self.entry_confirm.pack(pady=5)

        # Show/hide passphrase checkbox
        self.show_var = tk.IntVar()
        chk = tk.Checkbutton(self.top, text="Show Passphrase", variable=self.show_var, command=self.toggle_passphrase)
        chk.pack(pady=5)
        
        # Auto-generate RSA key checkbox
        self.auto_generate_key = tk.IntVar(value=1)
        key_chk = tk.Checkbutton(self.top, text="Auto-generate RSA key pair after registration", variable=self.auto_generate_key)
        key_chk.pack(pady=5)

        tk.Button(self.top, text="Register", command=self.register).pack(pady=20)
        tk.Button(self.top, text="Cancel", command=self.top.destroy).pack()

    def toggle_passphrase(self):
        if self.show_var.get():
            self.entry_passphrase.config(show="")
            self.entry_confirm.config(show="")
        else:
            self.entry_passphrase.config(show="*")
            self.entry_confirm.config(show="*")

    def register(self):
        username = self.entry_username.get().strip()
        email = self.entry_email.get().strip()
        passphrase = self.entry_passphrase.get()
        confirm = self.entry_confirm.get()

        if not username or not email or not passphrase or not confirm:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        # Validate email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            messagebox.showerror("Error", "Please enter a valid email address.")
            return

        if passphrase != confirm:
            messagebox.showerror("Error", "Passphrases do not match.")
            return
        
        # Passphrase validation
        if len(passphrase) < 8:
            messagebox.showerror("Error", "Passphrase must be at least 8 characters long.")
            return

        if not any(c.isupper() for c in passphrase):
            messagebox.showerror("Error", "Passphrase must contain at least one uppercase letter.")
            return
        
        if not any(c.isdigit() for c in passphrase):
            messagebox.showerror("Error", "Passphrase must contain at least one digit.")
            return
        
        if not bool(re.findall(r"[^a-zA-Z0-9\s]", passphrase)):
            messagebox.showerror("Error", "Passphrase must contain at least one special character.")
            return

        try:
            # Create user in database
            success, result = self.db_manager.create_user(username, email, passphrase)
            
            if not success:
                messagebox.showerror("Error", f"Registration failed: {result}")
                return
            
            user_id = result
            
            # Auto-generate RSA key pair if requested
            if self.auto_generate_key.get():
                try:
                    # Show progress
                    progress_window = self.show_progress("Generating RSA key pair...")
                    self.top.update()
                    
                    # Generate key pair using the same passphrase
                    key_data = self.rsa_manager.create_key_pair_with_encryption(email, passphrase)
                    
                    # Save to database
                    key_success, key_result = self.db_manager.save_rsa_key(
                        user_id,
                        email,
                        key_data['public_key'],
                        key_data['private_key_encrypted'],
                        key_data['key_size']
                    )
                    
                    progress_window.destroy()
                    
                    if key_success:
                        messagebox.showinfo("Success", 
                                          f"User '{username}' registered successfully!\n\n"
                                          f"RSA Key Pair Generated:\n"
                                          f"- Key Size: {key_data['key_size']} bits\n"
                                          f"- Email: {email}\n"
                                          f"- Expires: {key_data['expires_at'].strftime('%Y-%m-%d')}\n"
                                          f"- Valid for: 90 days")
                    else:
                        messagebox.showwarning("Partial Success", 
                                             f"User '{username}' registered successfully!\n"
                                             f"However, RSA key generation failed: {key_result}\n"
                                             f"You can generate keys later from the main menu.")
                
                except Exception as e:
                    if 'progress_window' in locals():
                        progress_window.destroy()
                    messagebox.showwarning("Partial Success", 
                                         f"User '{username}' registered successfully!\n"
                                         f"However, RSA key generation failed: {str(e)}\n"
                                         f"You can generate keys later from the main menu.")
            else:
                messagebox.showinfo("Success", f"User '{username}' registered successfully!")

            self.top.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Registration failed: {str(e)}")
    
    def show_progress(self, message):
        """Show progress dialog"""
        progress = tk.Toplevel(self.top)
        progress.title("Please Wait")
        progress.geometry("300x100")
        progress.resizable(False, False)
        progress.transient(self.top)
        progress.grab_set()
        
        # Center the window
        progress.update_idletasks()
        x = (progress.winfo_screenwidth() // 2) - (300 // 2)
        y = (progress.winfo_screenheight() // 2) - (100 // 2)
        progress.geometry(f"300x100+{x}+{y}")
        
        tk.Label(progress, text=message).pack(pady=20)
        
        # Simple progress bar simulation
        progress_frame = tk.Frame(progress)
        progress_frame.pack(pady=10)
        
        canvas = tk.Canvas(progress_frame, width=200, height=20, bg='white')
        canvas.pack()
        
        # Animate progress bar
        def animate():
            for i in range(0, 201, 10):
                canvas.delete("all")
                canvas.create_rectangle(0, 0, i, 20, fill='green')
                progress.update()
                progress.after(50)
        
        progress.after(100, animate)
        
        return progress
