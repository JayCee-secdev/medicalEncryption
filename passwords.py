# passwords.py
import hashlib

# Password policy
PASSWORD_MIN_LENGTH = 8


def hash_password(password: str, salt: str = "static_salt_change_me") -> str:
    """
    Simple SHA-256 hash with a static salt.
    NOTE: For a real system use per-user salts + Argon2/bcrypt/PBKDF2.
    """
    to_hash = (salt + password).encode("utf-8")
    return hashlib.sha256(to_hash).hexdigest()


def verify_password(password: str, stored_hash: str, salt: str = "static_salt_change_me") -> bool:
    """Compare a plain password with the stored hash."""
    return hash_password(password, salt) == stored_hash
