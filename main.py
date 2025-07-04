import tkinter as tk
from Crypto.PublicKey import RSA
import pyotp
import qrcode
from PIL import Image

print("OK! All packages imported successfully.")

# Import GUI modules
from gui.main_window import MainWindow

def main():
    """Main application entry point"""
    root = tk.Tk()
    
    # Configure root window
    root.withdraw()  # Hide root window initially
    
    # Create and show main window
    app = MainWindow(root)
    
    # Show the root window
    root.deiconify()
    
    # Start the GUI event loop
    root.mainloop()

if __name__ == "__main__":
    main()
