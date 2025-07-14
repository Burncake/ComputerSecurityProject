import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from modules.utils.db_helper import (
    get_user_key_list, get_user_role, promote_to_admin, demote_to_user,
    is_account_locked, set_account_lock
)
from modules.core import session
from modules.utils import logger

class AdminDashboardFrame(tk.Frame):
    def __init__(self, master, back_callback):
        super().__init__(master)
        self.master = master
        self.master.geometry("800x600")
        self.email = session.get_user()['email']
        self.back = back_callback
        self.pack(fill="both", expand=True)

        tk.Label(self, text="Admin Dashboard", font=("Helvetica",16)).pack(pady=5)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)

        self.tab_users = tk.Frame(self.notebook)
        self.tab_logs  = tk.Frame(self.notebook)
        self.notebook.add(self.tab_users, text="Users")
        self.notebook.add(self.tab_logs,  text="Logs")

        self.build_users_tab()
        self.build_logs_tab()

        tk.Button(self, text="Back", command=self.back).pack(pady=5)

    def build_users_tab(self):
        container = self.tab_users
        tv_frame = tk.Frame(container)
        tv_frame.pack(fill="both", expand=True, side="left", padx=(10,0), pady=10)

        cols = ("Email","Role","Locked")
        self.tree = ttk.Treeview(tv_frame, columns=cols, show="headings")
        vsb = ttk.Scrollbar(tv_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="left", fill="y")

        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=150, anchor="center")

        self.refresh_users()

        btns = tk.Frame(container)
        btns.pack(fill="y", side="right", padx=10, pady=20)

        def lock():
            sel = self.tree.selection()
            if not sel:
                messagebox.showerror("Error","Select a user.")
                return
            set_account_lock(sel[0], True)
            logger.log_info(f"Admin {self.email} locked '{sel[0]}'")
            self.refresh_users()

        def unlock():
            sel = self.tree.selection()
            if not sel:
                messagebox.showerror("Error","Select a user.")
                return
            set_account_lock(sel[0], False)
            logger.log_info(f"Admin {self.email} unlocked '{sel[0]}'")
            self.refresh_users()

        def promote():
            sel = self.tree.selection()
            if not sel:
                messagebox.showerror("Error","Select a user.")
                return
            promote_to_admin(sel[0])
            logger.log_info(f"Admin {self.email} promoted '{sel[0]}' to admin")
            self.refresh_users()

        def demote():
            sel = self.tree.selection()
            if not sel:
                messagebox.showerror("Error","Select a user.")
                return
            demote_to_user(sel[0])
            logger.log_info(f"Admin {self.email} demoted '{sel[0]}' to user")
            self.refresh_users()

        for txt, cmd in [
            ("Lock Account", lock),
            ("Unlock Account", unlock),
            ("Promote to Admin", promote),
            ("Demote to User", demote),
        ]:
            tk.Button(btns, text=txt, width=20, command=cmd).pack(pady=5)

    def refresh_users(self):
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        emails = [r[0] for r in get_user_key_list()]
        for email in emails:
            role = get_user_role(email)
            locked = "Yes" if is_account_locked(email) else "No"
            self.tree.insert("", "end", iid=email, values=(email, role, locked))

    def build_logs_tab(self):
        container = self.tab_logs
        tk.Label(container, text="System Log", font=("Helvetica", 14)).pack(pady=5)
        self.log_view = scrolledtext.ScrolledText(container, state="disabled", width=80, height=20)
        self.log_view.pack(fill="both", expand=True, padx=10, pady=(0,10))

    def refresh_logs(self):
        try:
            with open("data/logs/security.log","r") as f:
                content = f.read()
        except FileNotFoundError:
            content = "(no logs found)"
        self.log_view.config(state="normal")
        self.log_view.delete("1.0","end")
        self.log_view.insert("1.0", content)
        self.log_view.config(state="disabled")

    def on_tab_changed(self, event):
        selected = event.widget.tab('current')['text']
        if selected == "Users":
            self.refresh_users()
        elif selected == "Logs":
            self.refresh_logs()
