import os
import tkinter as tk
from tkinter import filedialog, messagebox

from vault import Vault

APP_NAME = "SmartVault"


class VaultWindow(tk.Tk):
    def __init__(self, db_path, passphrase):
        super().__init__()
        self.vault = Vault(db_path=db_path, passphrase=passphrase)

        self.title(APP_NAME)
        self.geometry("520x380")

        tk.Label(self, text=f"{APP_NAME} - {db_path}", font=("TkDefaultFont", 12, "bold")).pack(pady=8)

        button_row = tk.Frame(self)
        button_row.pack(pady=4)
        tk.Button(button_row, text="Add file(s)...", command=self.add_files).pack(side="left", padx=4)
        tk.Button(button_row, text="Extract selected...", command=self.extract_selected).pack(side="left", padx=4)
        tk.Button(button_row, text="Delete selected", command=self.delete_selected).pack(side="left", padx=4)

        self.listbox = tk.Listbox(self, width=70, height=14)
        self.listbox.pack(padx=10, pady=8, fill="both", expand=True)

        self.status = tk.Label(self, text="Ready", anchor="w")
        self.status.pack(fill="x", padx=10, pady=4)

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.refresh()

    def refresh(self):
        self.listbox.delete(0, tk.END)
        self._entries = self.vault.list_files()
        for _id, name, size in self._entries:
            self.listbox.insert(tk.END, f"{_id}\t{name}\t{size} bytes")

    def _selected_identifier(self):
        selection = self.listbox.curselection()
        if not selection:
            return None
        return self._entries[selection[0]][0]

    def add_files(self):
        paths = filedialog.askopenfilenames(title="Select files to encrypt")
        if not paths:
            return
        for path in paths:
            self.vault.add_file(path)
        self.refresh()
        self.status.config(text=f"Added {len(paths)} file(s)")

    def extract_selected(self):
        identifier = self._selected_identifier()
        if identifier is None:
            messagebox.showwarning(APP_NAME, "Select a file first.")
            return
        name = next(n for i, n, s in self._entries if i == identifier)
        output = filedialog.asksaveasfilename(title="Save decrypted file as", initialfile=name)
        if not output:
            return
        self.vault.extract_file(identifier, output)
        self.status.config(text=f"Extracted to {output}")

    def delete_selected(self):
        identifier = self._selected_identifier()
        if identifier is None:
            messagebox.showwarning(APP_NAME, "Select a file first.")
            return
        self.vault.remove_file(identifier)
        self.refresh()
        self.status.config(text="Deleted")

    def on_close(self):
        self.vault.close()
        self.destroy()


def launch(db_path, passphrase):
    app = VaultWindow(db_path, passphrase)
    app.mainloop()
