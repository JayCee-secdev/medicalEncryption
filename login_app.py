# login_app.py
import tkinter as tk
from tkinter import messagebox
import re
import os
import base64

from users_repo import load_users, save_users
from passwords import hash_password, verify_password, PASSWORD_MIN_LENGTH

# cryptography imports for key management
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


# ------------ EMAIL VALIDATION ------------
def validate_email(email):
    pattern = r"^[^@]+@[^@]+\.[^@]+$"
    return re.match(pattern, email) is not None


# ------------ CRYPTO HELPERS (per-user key pair) ------------
def generate_user_keypair():
    """
    Generate an RSA keypair for a user.
    Returns (public_pem_bytes, private_pem_bytes).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,   # good enough for class project
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # we'll encrypt ourselves
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_pem, private_pem


def _derive_fernet_key_from_password(password: str, salt: bytes) -> bytes:
    """
    PBKDF2-HMAC-SHA256 -> 32-byte key -> urlsafe base64 for Fernet.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key_bytes = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(key_bytes)


def encrypt_private_key_for_user(private_pem: bytes, password: str):
    """
    Encrypt private key with a key derived from the user's password.

    Returns (salt_b64_str, encrypted_private_key_b64_str).
    """
    salt = os.urandom(16)
    fernet_key = _derive_fernet_key_from_password(password, salt)
    f = Fernet(fernet_key)
    token = f.encrypt(private_pem)

    salt_b64 = base64.b64encode(salt).decode("utf-8")
    token_b64 = base64.b64encode(token).decode("utf-8")
    return salt_b64, token_b64


def decrypt_private_key_for_user(encrypted_private_key_b64: str, salt_b64: str, password: str):
    """
    Reverse of encrypt_private_key_for_user.
    Returns a cryptography private key object.
    """
    salt = base64.b64decode(salt_b64.encode("utf-8"))
    token = base64.b64decode(encrypted_private_key_b64.encode("utf-8"))

    fernet_key = _derive_fernet_key_from_password(password, salt)
    f = Fernet(fernet_key)
    private_pem = f.decrypt(token)

    private_key = serialization.load_pem_private_key(
        private_pem,
        password=None,
    )
    return private_key


class LoginApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Medical File Encryption - Patient Portal")
        self.geometry("700x500")
        self.minsize(600, 450)
        self.resizable(True, True)

        # Data
        self.users = load_users()
        self.current_username = None
        self.current_private_key = None   # decrypted RSA private key object

        # Frames
        self.login_frame = None
        self.register_frame = None

        self.show_login_frame()

    def clear_frames(self):
        if self.login_frame is not None:
            self.login_frame.destroy()
        if self.register_frame is not None:
            self.register_frame.destroy()

    # ------------ HOME / LOGIN PAGE ------------
    def show_login_frame(self):
        self.clear_frames()
        self.login_frame = tk.Frame(self, padx=20, pady=20)
        self.login_frame.pack(fill="both", expand=True)

        tk.Label(
            self.login_frame,
            text="Patient Login",
            font=("Arial", 16, "bold")
        ).grid(row=0, column=0, columnspan=2, pady=(0, 20))

        tk.Label(self.login_frame, text="Username:").grid(
            row=1, column=0, sticky="e", pady=5
        )
        self.login_username_entry = tk.Entry(self.login_frame, width=30)
        self.login_username_entry.grid(row=1, column=1, pady=5)

        tk.Label(self.login_frame, text="Password:").grid(
            row=2, column=0, sticky="e", pady=5
        )
        self.login_password_entry = tk.Entry(
            self.login_frame, width=30, show="*"
        )
        self.login_password_entry.grid(row=2, column=1, pady=5)

        login_button = tk.Button(
            self.login_frame, text="Login", width=15, command=self.login
        )
        login_button.grid(row=3, column=0, columnspan=2, pady=15)

        create_account_button = tk.Button(
            self.login_frame,
            text="Create Account",
            width=15,
            command=self.show_register_frame
        )
        create_account_button.grid(row=4, column=0, columnspan=2)

    # ------------ CREATE ACCOUNT PAGE ------------
    def show_register_frame(self):
        self.clear_frames()
        self.register_frame = tk.Frame(self, padx=20, pady=20)
        self.register_frame.pack(fill="both", expand=True)

        tk.Label(
            self.register_frame,
            text="Create Patient Account",
            font=("Arial", 16, "bold")
        ).grid(row=0, column=0, columnspan=2, pady=(0, 20))

        tk.Label(self.register_frame, text="First Name *").grid(
            row=1, column=0, sticky="e", pady=5
        )
        self.first_name_entry = tk.Entry(self.register_frame, width=30)
        self.first_name_entry.grid(row=1, column=1, pady=5)

        tk.Label(self.register_frame, text="Last Name *").grid(
            row=2, column=0, sticky="e", pady=5
        )
        self.last_name_entry = tk.Entry(self.register_frame, width=30)
        self.last_name_entry.grid(row=2, column=1, pady=5)

        tk.Label(self.register_frame, text="Mobile Number").grid(
            row=3, column=0, sticky="e", pady=5
        )
        self.mobile_entry = tk.Entry(self.register_frame, width=30)
        self.mobile_entry.grid(row=3, column=1, pady=5)

        tk.Label(self.register_frame, text="Email *").grid(
            row=4, column=0, sticky="e", pady=5
        )
        self.email_entry = tk.Entry(self.register_frame, width=30)
        self.email_entry.grid(row=4, column=1, pady=5)

        tk.Label(self.register_frame, text="Address *").grid(
            row=5, column=0, sticky="ne", pady=5
        )
        self.address_text = tk.Text(self.register_frame, width=30, height=3)
        self.address_text.grid(row=5, column=1, pady=5)

        tk.Label(self.register_frame, text="Username *").grid(
            row=6, column=0, sticky="e", pady=5
        )
        self.username_entry = tk.Entry(self.register_frame, width=30)
        self.username_entry.grid(row=6, column=1, pady=5)

        tk.Label(self.register_frame, text="Password *").grid(
            row=7, column=0, sticky="e", pady=5
        )
        self.password_entry = tk.Entry(self.register_frame, width=30, show="*")
        self.password_entry.grid(row=7, column=1, pady=5)

        tk.Label(self.register_frame, text="Confirm Password *").grid(
            row=8, column=0, sticky="e", pady=5
        )
        self.confirm_password_entry = tk.Entry(
            self.register_frame, width=30, show="*"
        )
        self.confirm_password_entry.grid(row=8, column=1, pady=5)

        create_button = tk.Button(
            self.register_frame,
            text="Create Account",
            width=15,
            command=self.create_account
        )
        create_button.grid(row=9, column=0, columnspan=2, pady=15)

        back_button = tk.Button(
            self.register_frame,
            text="Back to Home",
            width=15,
            command=self.show_login_frame
        )
        back_button.grid(row=10, column=0, columnspan=2)

    # ------------ LOGIN LOGIC ------------
    def login(self):
        from dashboard import Dashboard  # import here to avoid circular import

        username = self.login_username_entry.get().strip()
        password = self.login_password_entry.get().strip()

        if not username or not password:
            messagebox.showerror(
                "Error", "Please enter both username and password."
            )
            return

        if len(password) < PASSWORD_MIN_LENGTH:
            messagebox.showerror(
                "Error",
                f"Password must be at least {PASSWORD_MIN_LENGTH} characters long."
            )
            return

        if username not in self.users:
            messagebox.showerror("Error", "Invalid username or password.")
            return

        user_record = self.users[username]
        stored_hash = user_record["password_hash"]

        if not verify_password(password, stored_hash):
            messagebox.showerror("Error", "Invalid username or password.")
            return

        # ---- Password OK: unlock their private key ----
        try:
            private_key = decrypt_private_key_for_user(
                encrypted_private_key_b64=user_record["private_key_encrypted"],
                salt_b64=user_record["key_salt"],
                password=password,
            )
        except Exception:
            messagebox.showerror(
                "Error",
                "Login succeeded, but your encryption key could not be unlocked.\n"
                "The stored key data may be corrupted."
            )
            return

        self.current_username = username
        self.current_private_key = private_key

        # Go to dashboard
        self.clear_frames()
        dash = Dashboard(self, self)  # master=self, app=self
        dash.pack(fill="both", expand=True)

    # ------------ CREATE ACCOUNT LOGIC ------------
    def create_account(self):
        first_name = self.first_name_entry.get().strip()
        last_name = self.last_name_entry.get().strip()
        mobile = self.mobile_entry.get().strip()
        email = self.email_entry.get().strip()
        address = self.address_text.get("1.0", "end").strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        confirm_password = self.confirm_password_entry.get().strip()

        # Mandatory field validation
        if (
            not first_name
            or not last_name
            or not email
            or not address
            or not username
            or not password
        ):
            messagebox.showerror(
                "Error", "Please fill in all mandatory fields (*)."
            )
            return

        # Email validation
        if not validate_email(email):
            messagebox.showerror(
                "Error", "Please enter a valid email address."
            )
            return

        # Username uniqueness
        if username in self.users:
            messagebox.showerror(
                "Error",
                "This username is already taken. Please choose another one."
            )
            return

        # Password rules
        if len(password) < PASSWORD_MIN_LENGTH:
            messagebox.showerror(
                "Error",
                f"Password must be at least {PASSWORD_MIN_LENGTH} characters long."
            )
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        # Optional: basic mobile validation (digits only)
        if mobile and not mobile.isdigit():
            messagebox.showerror(
                "Error", "Mobile number should contain digits only."
            )
            return

        # ---- Generate per-user keypair and encrypt private key with their password ----
        public_pem, private_pem = generate_user_keypair()
        key_salt_b64, encrypted_private_b64 = encrypt_private_key_for_user(private_pem, password)
        public_b64 = base64.b64encode(public_pem).decode("utf-8")

        # Save new user
        self.users[username] = {
            "first_name": first_name,
            "last_name": last_name,
            "mobile": mobile,
            "email": email,
            "address": address,
            "password_hash": hash_password(password),

            # NEW FIELDS FOR ENCRYPTED COMMUNICATION
            "public_key": public_b64,
            "private_key_encrypted": encrypted_private_b64,
            "key_salt": key_salt_b64,
        }
        save_users(self.users)
        messagebox.showinfo(
            "Success", "Account created successfully! You can now log in."
        )
        self.show_login_frame()
