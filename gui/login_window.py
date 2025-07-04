import tkinter as tk
from tkinter import messagebox
import sys
import os

# Add the project root to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.auth.database import DatabaseManager
from gui.key_management_window import KeyManagementWindow

class LoginWindow:
    def __init__(self, master):
        self.master = master
        self.db_manager = DatabaseManager()
        
        self.top = tk.Toplevel(master)
        self.top.title("Login")
        self.top.geometry("350x250")
        self.top.resizable(False, False)
        
        # Center the window
        self.top.update_idletasks()
        x = (self.top.winfo_screenwidth() // 2) - (350 // 2)
        y = (self.top.winfo_screenheight() // 2) - (250 // 2)
        self.top.geometry(f"350x250+{x}+{y}")

        # Title
        title_label = tk.Label(self.top, text="User Login", font=("Arial", 14, "bold"))
        title_label.pack(pady=20)

        # Username
        tk.Label(self.top, text="Username:").pack(pady=5)
        self.entry_username = tk.Entry(self.top, width=30)
        self.entry_username.pack(pady=5)

        # Password
        tk.Label(self.top, text="Password:").pack(pady=5)
        self.entry_password = tk.Entry(self.top, width=30, show="*")
        self.entry_password.pack(pady=5)

        # Show password checkbox
        self.show_var = tk.IntVar()
        chk = tk.Checkbutton(self.top, text="Show Password", variable=self.show_var, command=self.toggle_password)
        chk.pack(pady=5)

        # Buttons
        button_frame = tk.Frame(self.top)
        button_frame.pack(pady=20)
        
        tk.Button(button_frame, text="Login", command=self.login, width=10).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Cancel", command=self.top.destroy, width=10).pack(side=tk.LEFT, padx=5)
        
        # Bind Enter key to login
        self.top.bind('<Return>', lambda event: self.login())
        
        # Focus on username entry
        self.entry_username.focus()

    def toggle_password(self):
        """Toggle password visibility"""
        if self.show_var.get():
            self.entry_password.config(show="")
        else:
            self.entry_password.config(show="*")

    def login(self):
        """Handle user login"""
        username = self.entry_username.get().strip()
        password = self.entry_password.get()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password.")
            return

        try:
            # Verify credentials
            success, user_id = self.db_manager.verify_user(username, password)
            
            if success:
                # Get user information
                user_info = self.db_manager.get_user_by_id(user_id)
                
                if user_info:
                    messagebox.showinfo("Success", f"Welcome back, {user_info['username']}!")
                    
                    # Close login window
                    self.top.destroy()
                    
                    # Open key management window
                    KeyManagementWindow(self.master, user_id, user_info)
                else:
                    messagebox.showerror("Error", "Failed to retrieve user information.")
            else:
                messagebox.showerror("Error", "Invalid username or password.")
                
        except Exception as e:
            messagebox.showerror("Error", f"Login failed: {str(e)}")


# For testing
if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()  # Hide main window
    
    app = LoginWindow(root)
    root.mainloop()
