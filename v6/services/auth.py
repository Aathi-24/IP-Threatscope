"""
User authentication and account management.

All user data is stored in a single JSON file (data/users.json) which
acts as the application's user database. No external database is needed.

Schema for data/users.json:
{
  "users": {
    "user@gmail.com": {
      "email": "user@gmail.com",
      "password_hash": "<werkzeug pbkdf2 hash>",
      "settings": {
        "mail_sender": "",
        "mail_recipient": "",
        "mail_app_password": "",
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "check_interval_minutes": 60,
        "missed_check_grace_minutes": 10
      },
      "ips": ["1.2.3.4", "8.8.8.8"],
      "scheduler_state": {
        "last_success_at": null,
        "last_success_iso": null,
        "last_alert_sent_for": null
      }
    }
  }
}

Thread-safety: reads and writes are wrapped in a threading.Lock so
background scheduler threads and web-request threads can't corrupt the
file if they happen to write at the same moment.
"""

import json
import os
import re
import threading

from werkzeug.security import generate_password_hash, check_password_hash

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USERS_FILE = os.path.join(_APP_DIR, "data", "users.json")

_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Low-level JSON helpers
# ---------------------------------------------------------------------------

def _load_db():
    """Load the full users database from disk. Returns {'users': {...}}."""
    if not os.path.exists(USERS_FILE):
        return {"users": {}}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        data.setdefault("users", {})
        return data
    except (json.JSONDecodeError, OSError):
        return {"users": {}}


def _save_db(db):
    """Write the full users database to disk atomically."""
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    tmp = USERS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)
    os.replace(tmp, USERS_FILE)


def _default_user(email):
    """Return a blank user record with sensible defaults."""
    return {
        "email": email,
        "password_hash": "",
        "settings": {
            "mail_sender": email,
            "mail_recipient": email,
            "mail_app_password": "",
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "check_interval_minutes": 60,
            "missed_check_grace_minutes": 10,
        },
        "ips": [],
        "scheduler_state": {
            "last_success_at": None,
            "last_success_iso": None,
            "last_alert_sent_for": None,
        },
    }


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

GMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@gmail\.com$", re.IGNORECASE)


def is_valid_gmail(email):
    """Return True only for valid @gmail.com addresses."""
    return bool(GMAIL_RE.match(email.strip()))


def is_strong_password(password):
    """Require at least 8 characters. Returns (ok: bool, message: str)."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    return True, ""


# ---------------------------------------------------------------------------
# Public API used by app.py
# ---------------------------------------------------------------------------

def get_user(email):
    """Return the user dict for *email*, or None if they don't exist."""
    with _lock:
        db = _load_db()
        return db["users"].get(email.strip().lower())


def all_users():
    """Return the full {email: user_dict} mapping (a snapshot copy)."""
    with _lock:
        db = _load_db()
        return dict(db["users"])


def register_user(email, password):
    """Create a new user account.

    Returns (success: bool, message: str).
    Fails if the email is not a Gmail address, the password is too weak,
    or the account already exists.
    """
    email = email.strip().lower()

    if not is_valid_gmail(email):
        return False, "Please use a valid Gmail address (@gmail.com) to register."

    ok, msg = is_strong_password(password)
    if not ok:
        return False, msg

    with _lock:
        db = _load_db()
        if email in db["users"]:
            return False, "An account with that email already exists."
        user = _default_user(email)
        user["password_hash"] = generate_password_hash(password)
        db["users"][email] = user
        _save_db(db)

    return True, "Account created successfully. You can now log in."


def verify_login(email, password):
    """Verify email + password.

    Returns (success: bool, message: str).
    """
    email = email.strip().lower()
    user = get_user(email)

    if user is None:
        return False, "No account found with that email address."

    if not check_password_hash(user["password_hash"], password):
        return False, "Incorrect password."

    return True, "Login successful."


def change_password(email, current_password, new_password):
    """Change a user's password after verifying the current one.

    Returns (success: bool, message: str).
    """
    email = email.strip().lower()

    ok_login, msg = verify_login(email, current_password)
    if not ok_login:
        return False, f"Current password is incorrect: {msg}"

    ok_strength, msg = is_strong_password(new_password)
    if not ok_strength:
        return False, msg

    if current_password == new_password:
        return False, "New password must be different from the current password."

    with _lock:
        db = _load_db()
        if email not in db["users"]:
            return False, "User not found."
        db["users"][email]["password_hash"] = generate_password_hash(new_password)
        _save_db(db)

    return True, "Password changed successfully."


def save_user_settings(email, settings):
    """Persist a user's mail/scheduler settings dict.

    Only the keys that exist in the current record are updated, so
    unknown keys from a form POST can't pollute the data.
    """
    email = email.strip().lower()
    allowed_keys = {
        "mail_sender", "mail_recipient", "mail_app_password",
        "smtp_server", "smtp_port",
        "check_interval_minutes", "missed_check_grace_minutes",
    }
    with _lock:
        db = _load_db()
        if email not in db["users"]:
            return False, "User not found."
        current = db["users"][email]["settings"]
        for key in allowed_keys:
            if key in settings:
                val = settings[key]
                # Coerce numeric fields
                if key in ("smtp_port", "check_interval_minutes", "missed_check_grace_minutes"):
                    try:
                        val = int(val)
                    except (TypeError, ValueError):
                        continue
                current[key] = val
        _save_db(db)
    return True, "Settings saved."


def get_user_ips(email):
    """Return the list of IPs stored for this user."""
    user = get_user(email)
    return list(user["ips"]) if user else []


def add_user_ip(email, ip):
    """Append an IP to the user's list (no duplicates).

    Returns (success: bool, message: str).
    """
    import ipaddress as _ip
    email = email.strip().lower()
    ip = ip.strip()

    try:
        _ip.ip_address(ip)
    except ValueError:
        return False, f"'{ip}' is not a valid IP address."

    with _lock:
        db = _load_db()
        if email not in db["users"]:
            return False, "User not found."
        ips = db["users"][email]["ips"]
        if ip in ips:
            return False, f"{ip} is already in your list."
        ips.append(ip)
        _save_db(db)

    return True, f"{ip} added."


def add_user_ips_bulk(email, raw_text):
    """Parse a newline/comma-separated block of IPs and add all valid ones.

    Returns (added: list, skipped: list).
    """
    import ipaddress as _ip
    email = email.strip().lower()
    added = []
    skipped = []

    candidates = re.split(r"[\n\r,;]+", raw_text)
    with _lock:
        db = _load_db()
        if email not in db["users"]:
            return [], candidates
        existing = set(db["users"][email]["ips"])
        for raw in candidates:
            ip = raw.strip()
            if not ip:
                continue
            try:
                _ip.ip_address(ip)
            except ValueError:
                skipped.append(ip)
                continue
            if ip in existing:
                skipped.append(ip)
                continue
            existing.add(ip)
            db["users"][email]["ips"].append(ip)
            added.append(ip)
        _save_db(db)

    return added, skipped


def remove_user_ip(email, ip):
    """Remove an IP from the user's list.

    Returns (success: bool, message: str).
    """
    email = email.strip().lower()
    with _lock:
        db = _load_db()
        if email not in db["users"]:
            return False, "User not found."
        ips = db["users"][email]["ips"]
        if ip not in ips:
            return False, f"{ip} not found in your list."
        ips.remove(ip)
        _save_db(db)
    return True, f"{ip} removed."


def get_user_scheduler_state(email):
    """Return the per-user scheduler state dict."""
    user = get_user(email)
    if user is None:
        return {"last_success_at": None, "last_success_iso": None, "last_alert_sent_for": None}
    return dict(user.get("scheduler_state", {}))


def save_user_scheduler_state(email, state):
    """Overwrite the per-user scheduler state dict in users.json."""
    email = email.strip().lower()
    with _lock:
        db = _load_db()
        if email not in db["users"]:
            return
        db["users"][email]["scheduler_state"] = state
        _save_db(db)
