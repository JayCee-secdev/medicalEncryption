# users_repo.py
import json
import os

DATA_DIR = "data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")


def ensure_data_dir():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR, exist_ok=True)


def load_users():
    """Load all users from the JSON file (or return empty dict)."""
    ensure_data_dir()
    if not os.path.exists(USERS_FILE):
        return {}

    with open(USERS_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def save_users(users: dict):
    """Persist the given users dict to disk."""
    ensure_data_dir()
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)
