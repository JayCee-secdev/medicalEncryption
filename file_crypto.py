# file_crypto.py
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


def encrypt_file_for_recipients(file_bytes: bytes, recipients_public_pems: dict[str, bytes]):
    """
    recipients_public_pems = { "alice": public_pem_bytes, "bob": public_pem_bytes }

    Returns:
        ciphertext_bytes,
        { username: encrypted_sym_key_b64_str }
    """
    # 1) Random symmetric key
    sym_key = Fernet.generate_key()
    f = Fernet(sym_key)

    # 2) Encrypt file
    ciphertext = f.encrypt(file_bytes)

    # 3) Encrypt sym_key for each recipient
    enc_keys = {}
    for username, pub_pem in recipients_public_pems.items():
        public_key = serialization.load_pem_public_key(pub_pem)
        enc = public_key.encrypt(
            sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        enc_keys[username] = base64.b64encode(enc).decode("utf-8")

    return ciphertext, enc_keys


def decrypt_file_for_user(ciphertext: bytes, encrypted_sym_key_b64: str, private_key):
    """
    Decrypt file for a given user using their private RSA key.
    """
    sym_key_encrypted = base64.b64decode(encrypted_sym_key_b64.encode("utf-8"))
    sym_key = private_key.decrypt(
        sym_key_encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    f = Fernet(sym_key)
    return f.decrypt(ciphertext)
