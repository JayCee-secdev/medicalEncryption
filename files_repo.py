# files_repo.py
import json
import os
import uuid

DATA_DIR = "data"
FILES_FILE = os.path.join(DATA_DIR, "files.json")
ENCRYPTED_DIR = "encrypted_files"


def ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(ENCRYPTED_DIR, exist_ok=True)


def load_files():
    ensure_dirs()
    if not os.path.exists(FILES_FILE):
        return {}
    with open(FILES_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def save_files(files: dict):
    ensure_dirs()
    with open(FILES_FILE, "w") as f:
        json.dump(files, f, indent=4)


def save_encrypted_file(owner: str, original_filename: str,
                        ciphertext: bytes, recipients_enc_keys: dict[str, str]) -> str:
    """
    Save encrypted file on disk and metadata in files.json.

    recipients_enc_keys = { username: encrypted_sym_key_b64_str }
    Returns: file_id
    """
    ensure_dirs()
    files = load_files()

    file_id = uuid.uuid4().hex
    ciphertext_path = os.path.join(ENCRYPTED_DIR, f"{file_id}.bin")

    # Write ciphertext to disk
    with open(ciphertext_path, "wb") as f:
        f.write(ciphertext)

    # Build recipients structure
    recipients_meta = {}
    for uname, enc_key_b64 in recipients_enc_keys.items():
        recipients_meta[uname] = {"encrypted_sym_key": enc_key_b64}

    files[file_id] = {
        "owner": owner,
        "original_filename": original_filename,
        "ciphertext_path": ciphertext_path,
        "recipients": recipients_meta,
    }

    save_files(files)
    return file_id


def list_files_for_user(username: str):
    """
    Returns dict {file_id: file_meta} where the user is a recipient.
    """
    files = load_files()
    result = {}
    for fid, meta in files.items():
        if "recipients" in meta and username in meta["recipients"]:
            result[fid] = meta
    return result


def get_file(file_id: str):
    """Get metadata for a single file by id (or None)."""
    files = load_files()
    return files.get(file_id)
