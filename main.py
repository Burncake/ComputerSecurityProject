import os
from modules.utils.db_helper import init_db
from modules.key_mgmt.rsa_helper import init_rsa_db
import tkinter as tk
from gui.main_window import MainWindow

if __name__ == "__main__":
    if not os.path.exists("data/users.db"):
        init_db()
    if not os.path.exists("data/security_system.db"):
        init_rsa_db()
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()