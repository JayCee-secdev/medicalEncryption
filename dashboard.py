# dashboard.py
import tkinter as tk
from tkinter import messagebox, filedialog

import base64
import os

from file_crypto import encrypt_file_for_recipients, decrypt_file_for_user
from files_repo import save_encrypted_file, list_files_for_user, get_file


class Dashboard(tk.Frame):
    def __init__(self, master, app):
        """
        master: Tk root
        app: LoginApp instance (has .current_username, .current_private_key, .users)
        """
        super().__init__(master, padx=20, pady=20)
        self.app = app

        # mapping from listbox index -> file_id
        self.files_index_to_id = []

        # Make the bottom part expand when window resizes
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(2, weight=1)
        self.grid_rowconfigure(7, weight=1)   # row for files_listbox

        tk.Label(
            self,
            text=f"Welcome, {self.app.current_username}",
            font=("Arial", 16, "bold")
        ).grid(row=0, column=0, columnspan=3, pady=(0, 10))

        # ---- Send file section ----
        tk.Label(self, text="Send Encrypted File", font=("Arial", 12, "bold")).grid(
            row=1, column=0, columnspan=3, sticky="w", pady=(10, 5)
        )

        self.file_path_var = tk.StringVar()
        tk.Entry(self, textvariable=self.file_path_var, width=40, state="readonly").grid(
            row=2, column=0, columnspan=2, sticky="w", pady=2
        )
        tk.Button(self, text="Browse...", command=self.browse_file).grid(
            row=2, column=2, sticky="w", padx=5
        )

        tk.Label(self, text="Select recipients:").grid(
            row=3, column=0, sticky="w", pady=(8, 2)
        )

        # Recipients list + scrollbar
        self.recipients_listbox = tk.Listbox(self, selectmode=tk.MULTIPLE, height=5, width=30)
        recip_scroll = tk.Scrollbar(self, orient="vertical", command=self.recipients_listbox.yview)
        self.recipients_listbox.configure(yscrollcommand=recip_scroll.set)

        self.recipients_listbox.grid(row=4, column=0, sticky="nsew")
        recip_scroll.grid(row=4, column=1, sticky="ns")

        self.populate_recipients_list()

        tk.Button(self, text="Send Encrypted", command=self.send_encrypted).grid(
            row=5, column=0, columnspan=3, pady=(8, 15)
        )

        # ---- Files shared with user ----
        tk.Label(self, text="Files shared with you:", font=("Arial", 12, "bold")).grid(
            row=6, column=0, columnspan=3, sticky="w", pady=(10, 5)
        )

        # Files list + scrollbar
        self.files_listbox = tk.Listbox(self, height=8, width=60)
        files_scroll = tk.Scrollbar(self, orient="vertical", command=self.files_listbox.yview)
        self.files_listbox.configure(yscrollcommand=files_scroll.set)

        self.files_listbox.grid(row=7, column=0, columnspan=2, sticky="nsew")
        files_scroll.grid(row=7, column=2, sticky="ns")

        self.refresh_files_list()

        tk.Button(self, text="Open / Decrypt Selected", command=self.open_selected_file).grid(
            row=8, column=0, pady=(10, 0), sticky="w"
        )

        tk.Button(self, text="Logout", command=self.logout).grid(
            row=8, column=2, pady=(10, 0), sticky="e"
        )

    # ---------- UI helpers ----------
    def populate_recipients_list(self):
        """Fill the recipients listbox with all usernames except current user."""
        self.recipients_listbox.delete(0, tk.END)
        for uname in self.app.users.keys():
            if uname != self.app.current_username:
                self.recipients_listbox.insert(tk.END, uname)

    def refresh_files_list(self):
        """Reload list of files shared with the current user."""
        self.files_listbox.delete(0, tk.END)
        self.files_index_to_id = []   # reset mapping and rebuild

        files = list_files_for_user(self.app.current_username)
        for fid, meta in files.items():
            owner = meta.get("owner", "?")
            filename = meta.get("original_filename", "unknown")
            line = f"{fid[:8]}... | From: {owner} | {filename}"
            self.files_index_to_id.append(fid)
            self.files_listbox.insert(tk.END, line)

    # ---------- Actions ----------
    def browse_file(self):
        path = filedialog.askopenfilename(title="Select file to encrypt")
        if path:
            self.file_path_var.set(path)

    def send_encrypted(self):
        path = self.file_path_var.get()
        if not path:
            messagebox.showerror("Error", "Please choose a file first.")
            return

        # Get selected recipients
        selected_indices = self.recipients_listbox.curselection()
        if not selected_indices:
            messagebox.showerror("Error", "Please select at least one recipient.")
            return

        recipients = []
        for idx in selected_indices:
            recipients.append(self.recipients_listbox.get(idx))

        # Build dict {username: public_pem_bytes}
        recipients_public_pems = {}
        for uname in recipients:
            user = self.app.users.get(uname)
            if not user:
                messagebox.showerror("Error", f"User '{uname}' not found.")
                return
            public_b64 = user["public_key"]
            public_pem = base64.b64decode(public_b64.encode("utf-8"))
            recipients_public_pems[uname] = public_pem

        # Also allow sender to decrypt their own file (optional but useful)
        if self.app.current_username not in recipients_public_pems:
            user_self = self.app.users.get(self.app.current_username)
            if user_self:
                public_b64_self = user_self["public_key"]
                public_pem_self = base64.b64decode(public_b64_self.encode("utf-8"))
                recipients_public_pems[self.app.current_username] = public_pem_self

        # Read file bytes
        try:
            with open(path, "rb") as f:
                file_bytes = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file:\n{e}")
            return

        # Encrypt
        try:
            ciphertext, enc_keys = encrypt_file_for_recipients(file_bytes, recipients_public_pems)
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed:\n{e}")
            return

        # Save metadata & ciphertext
        filename_only = os.path.basename(path)
        try:
            file_id = save_encrypted_file(
                owner=self.app.current_username,
                original_filename=filename_only,
                ciphertext=ciphertext,
                recipients_enc_keys=enc_keys,
            )
        except Exception as e:
            messagebox.showerror("Error", f"Saving encrypted file failed:\n{e}")
            return

        messagebox.showinfo("Success", f"Encrypted file sent! (ID: {file_id[:8]}...)")
        self.refresh_files_list()
        self.file_path_var.set("")
        self.recipients_listbox.selection_clear(0, tk.END)

    def open_selected_file(self):
        selection = self.files_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "Please select a file first.")
            return

        idx = selection[0]
        # extra safety: check bounds
        if idx < 0 or idx >= len(self.files_index_to_id):
            messagebox.showerror("Error", "Internal file list out of sync. Try refreshing.")
            self.refresh_files_list()
            return

        file_id = self.files_index_to_id[idx]
        meta = get_file(file_id)
        if not meta:
            messagebox.showerror("Error", "File metadata not found.")
            return

        recipients_meta = meta.get("recipients", {})
        user_rec = recipients_meta.get(self.app.current_username)
        if not user_rec:
            messagebox.showerror("Error", "You are not authorized to open this file.")
            return

        enc_key_b64 = user_rec.get("encrypted_sym_key")
        ciphertext_path = meta.get("ciphertext_path")
        if not ciphertext_path or not os.path.exists(ciphertext_path):
            messagebox.showerror("Error", "Encrypted file not found on disk.")
            return

        try:
            with open(ciphertext_path, "rb") as f:
                ciphertext = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read encrypted file:\n{e}")
            return

        # Decrypt
        try:
            plaintext = decrypt_file_for_user(
                ciphertext,
                enc_key_b64,
                self.app.current_private_key
            )
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed:\n{e}")
            return

        # Ask where to save
        suggested_name = meta.get("original_filename", "decrypted_file")
        save_path = filedialog.asksaveasfilename(
            title="Save decrypted file as",
            initialfile=suggested_name
        )
        if not save_path:
            return

        try:
            with open(save_path, "wb") as f:
                f.write(plaintext)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save decrypted file:\n{e}")
            return

        messagebox.showinfo("Success", f"Decrypted file saved to:\n{save_path}")

    def logout(self):
        # Reset current user info
        self.app.current_username = None
        self.app.current_private_key = None

        # Remove this dashboard frame from the window
        self.destroy()

        # Show the login screen again
        self.app.show_login_frame()