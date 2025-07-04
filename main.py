import os
from modules.utils.db_helper import init_db
import tkinter as tk
from gui.main_window import MainWindow

if __name__ == "__main__":
    if not os.path.exists("data/users.db"):
        init_db()
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()
