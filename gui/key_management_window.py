import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
import os
import sys
import base64

# Add the project root to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.key_mgmt.rsa_manager import RSAKeyManager
from modules.auth.database import DatabaseManager

class KeyManagementWindow:
    def __init__(self, master, user_id, user_info):
        self.master = master
        self.user_id = user_id
        self.user_info = user_info
        self.rsa_manager = RSAKeyManager()
        self.db_manager = DatabaseManager()
        
        self.top = tk.Toplevel(master)
        self.top.title("RSA Key Management")
        self.top.geometry("800x600")
        self.top.resizable(True, True)
        
        self.create_widgets()
        self.refresh_key_list()
    
    def create_widgets(self):
        """Create GUI widgets"""
        # Main frame
        main_frame = ttk.Frame(self.top)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(main_frame, text=f"RSA Key Management - {self.user_info['username']}", 
                               font=("Arial", 14, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Button(button_frame, text="Generate New Key Pair", 
                  command=self.generate_new_key_pair).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="View Key Status", 
                  command=self.view_key_status).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Export Keys", 
                  command=self.export_keys).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Refresh", 
                  command=self.refresh_key_list).pack(side=tk.LEFT, padx=(0, 10))
        
        # Key list frame
        list_frame = ttk.LabelFrame(main_frame, text="Your RSA Keys")
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for key list
        columns = ("ID", "Email", "Key Size", "Created", "Expires", "Status", "Days Left")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=10)
        
        # Configure columns
        self.tree.heading("ID", text="ID")
        self.tree.heading("Email", text="Email")
        self.tree.heading("Key Size", text="Key Size")
        self.tree.heading("Created", text="Created")
        self.tree.heading("Expires", text="Expires")
        self.tree.heading("Status", text="Status")
        self.tree.heading("Days Left", text="Days Left")
        
        # Configure column widths
        self.tree.column("ID", width=50)
        self.tree.column("Email", width=150)
        self.tree.column("Key Size", width=80)
        self.tree.column("Created", width=120)
        self.tree.column("Expires", width=120)
        self.tree.column("Status", width=80)
        self.tree.column("Days Left", width=80)
        
        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack treeview and scrollbar
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Details frame
        details_frame = ttk.LabelFrame(main_frame, text="Key Details")
        details_frame.pack(fill=tk.X, pady=(20, 0))
        
        self.details_text = tk.Text(details_frame, height=8, wrap=tk.WORD)
        details_scroll = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, command=self.details_text.yview)
        self.details_text.configure(yscrollcommand=details_scroll.set)
        
        self.details_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        details_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind treeview selection
        self.tree.bind('<<TreeviewSelect>>', self.on_key_select)
    
    def refresh_key_list(self):
        """Refresh the key list"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Get keys from database
        keys = self.db_manager.get_user_keys(self.user_id)
        
        for key in keys:
            # Calculate days until expiry
            expires_date = datetime.fromisoformat(key['expires_at'].replace('Z', '+00:00'))
            days_left = self.rsa_manager.get_days_until_expiry(expires_date)
            
            # Determine status
            if not key['is_active']:
                status = "Inactive"
            elif self.rsa_manager.is_key_expired(expires_date):
                status = "Expired"
            else:
                status = "Active"
            
            # Format dates
            created = datetime.fromisoformat(key['created_at'].replace('Z', '+00:00')).strftime("%Y-%m-%d %H:%M")
            expires = expires_date.strftime("%Y-%m-%d %H:%M")
            
            self.tree.insert("", tk.END, values=(
                key['id'],
                key['email'],
                f"{key['key_size']} bit",
                created,
                expires,
                status,
                f"{days_left} days"
            ))
    
    def on_key_select(self, event):
        """Handle key selection"""
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            key_id = item['values'][0]
            
            # Get full key details
            keys = self.db_manager.get_user_keys(self.user_id)
            selected_key = next((k for k in keys if k['id'] == key_id), None)
            
            if selected_key:
                self.display_key_details(selected_key)
    
    def display_key_details(self, key):
        """Display detailed key information"""
        self.details_text.delete(1.0, tk.END)
        
        details = f"""Key ID: {key['id']}
Email: {key['email']}
Key Size: {key['key_size']} bits
Created: {key['created_at']}
Expires: {key['expires_at']}
Status: {'Active' if key['is_active'] else 'Inactive'}

Public Key (Base64):
{self.rsa_manager.format_key_for_display(key['public_key'], 100)}

Private Key (Encrypted):
{self.rsa_manager.format_key_for_display(key['private_key_encrypted'], 100)}
"""
        
        self.details_text.insert(tk.END, details)
    
    def generate_new_key_pair(self):
        """Generate new RSA key pair"""
        # Create dialog for passphrase
        dialog = KeyGenerationDialog(self.top, self.user_info['email'])
        self.top.wait_window(dialog.top)
        
        if hasattr(dialog, 'result') and dialog.result:
            passphrase = dialog.result
            
            try:
                # Show progress
                progress_window = self.show_progress("Generating RSA key pair...")
                self.top.update()
                
                # Generate key pair
                key_data = self.rsa_manager.create_key_pair_with_encryption(
                    self.user_info['email'], passphrase)
                
                # Save to database
                success, result = self.db_manager.save_rsa_key(
                    self.user_id,
                    self.user_info['email'],
                    key_data['public_key'],
                    key_data['private_key_encrypted'],
                    key_data['key_size']
                )
                
                progress_window.destroy()
                
                if success:
                    messagebox.showinfo("Success", 
                                      f"RSA key pair generated successfully!\n"
                                      f"Key ID: {result}\n"
                                      f"Key Size: {key_data['key_size']} bits\n"
                                      f"Expires: {key_data['expires_at'].strftime('%Y-%m-%d')}")
                    self.refresh_key_list()
                else:
                    messagebox.showerror("Error", f"Failed to save key: {result}")
                    
            except Exception as e:
                if 'progress_window' in locals():
                    progress_window.destroy()
                messagebox.showerror("Error", f"Failed to generate key pair: {str(e)}")
    
    def view_key_status(self):
        """View detailed key status"""
        active_key = self.db_manager.get_active_key(self.user_id)
        
        if active_key:
            expires_date = datetime.fromisoformat(active_key['expires_at'].replace('Z', '+00:00'))
            days_left = self.rsa_manager.get_days_until_expiry(expires_date)
            
            status_msg = f"""Active Key Status:
            
Key ID: {active_key['id']}
Email: {active_key['email']}
Key Size: {active_key['key_size']} bits
Created: {active_key['created_at']}
Expires: {active_key['expires_at']}
Days until expiry: {days_left} days

Status: {'Expired' if days_left <= 0 else 'Active'}
"""
            
            if days_left <= 7:
                status_msg += "\n⚠️ WARNING: Key expires soon! Consider generating a new key."
            
        else:
            status_msg = "No active RSA key found.\nPlease generate a new key pair."
        
        messagebox.showinfo("Key Status", status_msg)
    
    def export_keys(self):
        """Export keys to PEM files"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a key to export.")
            return
        
        item = self.tree.item(selection[0])
        key_id = item['values'][0]
        
        # Get key details
        keys = self.db_manager.get_user_keys(self.user_id)
        selected_key = next((k for k in keys if k['id'] == key_id), None)
        
        if not selected_key:
            messagebox.showerror("Error", "Key not found.")
            return
        
        # Ask for export directory
        export_dir = filedialog.askdirectory(title="Select Export Directory")
        if not export_dir:
            return
        
        try:
            # Export public key
            public_key_data = base64.b64decode(selected_key['public_key'])
            pub_filename = f"rsa_public_key_{key_id}.pem"
            pub_path = os.path.join(export_dir, pub_filename)
            
            with open(pub_path, 'wb') as f:
                f.write(public_key_data)
            
            # Export encrypted private key
            priv_filename = f"rsa_private_key_encrypted_{key_id}.pem"
            priv_path = os.path.join(export_dir, priv_filename)
            
            with open(priv_path, 'w') as f:
                f.write("-----BEGIN ENCRYPTED PRIVATE KEY-----\n")
                encrypted_data = selected_key['private_key_encrypted']
                for i in range(0, len(encrypted_data), 64):
                    f.write(encrypted_data[i:i+64] + "\n")
                f.write("-----END ENCRYPTED PRIVATE KEY-----\n")
            
            messagebox.showinfo("Success", 
                               f"Keys exported successfully:\n"
                               f"Public key: {pub_path}\n"
                               f"Private key: {priv_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export keys: {str(e)}")
    
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
        
        ttk.Label(progress, text=message).pack(pady=20)
        ttk.Progressbar(progress, mode='indeterminate').pack(pady=10)
        
        return progress


class KeyGenerationDialog:
    def __init__(self, parent, email):
        self.top = tk.Toplevel(parent)
        self.top.title("Generate RSA Key Pair")
        self.top.geometry("400x250")
        self.top.resizable(False, False)
        self.top.transient(parent)
        self.top.grab_set()
        
        # Center the window
        self.top.update_idletasks()
        x = (self.top.winfo_screenwidth() // 2) - (400 // 2)
        y = (self.top.winfo_screenheight() // 2) - (250 // 2)
        self.top.geometry(f"400x250+{x}+{y}")
        
        self.result = None
        
        # Main frame
        main_frame = ttk.Frame(self.top)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        ttk.Label(main_frame, text="Generate New RSA Key Pair", 
                 font=("Arial", 12, "bold")).pack(pady=(0, 20))
        
        # Email (read-only)
        ttk.Label(main_frame, text="Email:").pack(anchor=tk.W)
        email_entry = ttk.Entry(main_frame, width=50)
        email_entry.insert(0, email)
        email_entry.config(state='readonly')
        email_entry.pack(pady=(0, 10))
        
        # Passphrase
        ttk.Label(main_frame, text="Passphrase (for private key encryption):").pack(anchor=tk.W)
        self.passphrase_entry = ttk.Entry(main_frame, width=50, show="*")
        self.passphrase_entry.pack(pady=(0, 10))
        
        # Confirm passphrase
        ttk.Label(main_frame, text="Confirm Passphrase:").pack(anchor=tk.W)
        self.confirm_entry = ttk.Entry(main_frame, width=50, show="*")
        self.confirm_entry.pack(pady=(0, 20))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Generate", command=self.generate).pack(side=tk.RIGHT, padx=(10, 0))
        ttk.Button(button_frame, text="Cancel", command=self.cancel).pack(side=tk.RIGHT)
        
        # Focus on passphrase entry
        self.passphrase_entry.focus()
    
    def generate(self):
        """Generate key with validation"""
        passphrase = self.passphrase_entry.get()
        confirm = self.confirm_entry.get()
        
        if not passphrase:
            messagebox.showerror("Error", "Please enter a passphrase.")
            return
        
        if len(passphrase) < 8:
            messagebox.showerror("Error", "Passphrase must be at least 8 characters long.")
            return
        
        if passphrase != confirm:
            messagebox.showerror("Error", "Passphrases do not match.")
            return
        
        self.result = passphrase
        self.top.destroy()
    
    def cancel(self):
        """Cancel generation"""
        self.top.destroy()


# For testing
if __name__ == "__main__":
    import base64
    
    root = tk.Tk()
    root.withdraw()  # Hide main window
    
    # Test user info
    user_info = {
        'id': 1,
        'username': 'testuser',
        'email': 'test@example.com'
    }
    
    app = KeyManagementWindow(root, 1, user_info)
    root.mainloop()
