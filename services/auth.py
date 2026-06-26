"""
User authentication and account management.

Users are created by a NAKOA Technologies admin (via create_user.py, or
through the in-app Admin -> Users screen). Self-registration is not
available through the web interface.

Role model:
  Any account whose email domain is "nakoatech.com" is an ADMIN.
  Every other domain is a regular USER.
  Role is derived from the email domain at login time -- it is never
  stored, so there is nothing to tamper with in users.json.

Schema for data/users.json:
{
  "users": {
    "user@company.com": {
      "email": "user@company.com",
      "password_hash": "<werkzeug pbkdf2 hash>",
      "settings": {
        "check_interval_minutes": 60,
        "missed_check_grace_minutes": 10
      },
      "mail_settings": {
        "mail_sender":        "",
        "mail_smtp_password": "",
        "mail_recipient":     "",
        "smtp_server":        "",
        "smtp_port":          587,
        "smtp_security":      "TLS"
      },
      "ips": [],
      "scheduler_state": {
        "last_success_at":    null,
        "last_success_iso":   null,
        "last_alert_sent_for": null
      }
    }
  }
}

NOTE: "mail_settings" is editable only by accounts on the admin domain,
via the Admin Console -> Email Configuration screen. Regular users never
see or edit their own mail_settings -- there is no form for it in the
user-facing Settings page. The FLASK_SECRET_KEY still comes from .env.
"""

import json
import os
import re
import threading

from werkzeug.security import generate_password_hash, check_password_hash

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USERS_FILE = os.path.join(_APP_DIR, "data", "users.json")

_lock = threading.Lock()

# -- Role model ---------------------------------------------------------------
ADMIN_DOMAIN = "nakoatech.com"


def get_role_for_email(email):
    """Derive role purely from the email domain. Never stored -- always
    recomputed, so there's no 'role' field in users.json to tamper with."""
    email = (email or "").strip().lower()
    domain = email.rsplit("@", 1)[-1] if "@" in email else ""
    return "admin" if domain == ADMIN_DOMAIN else "user"


def is_admin_email(email):
    return get_role_for_email(email) == "admin"


# ── Low-level JSON helpers ───────────────────────────────────────────────────

def _load_db():
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
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    tmp = USERS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)
    os.replace(tmp, USERS_FILE)


def _default_user(email):
    return {
        "email": email,
        "password_hash": "",
        "settings": {
            "check_interval_minutes":     60,
            "missed_check_grace_minutes": 10,
        },
        "mail_settings": {
            "mail_sender":        "",
            "mail_smtp_password": "",
            "mail_recipient":     "",
            "smtp_server":        "",
            "smtp_port":          587,
            "smtp_security":      "TLS",
        },
        "ips": [],
        "scheduler_state": {
            "last_success_at":    None,
            "last_success_iso":   None,
            "last_alert_sent_for": None,
        },
    }


# ── Validation ───────────────────────────────────────────────────────────────

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def is_valid_email(email):
    return bool(EMAIL_RE.match(email.strip()))


def is_strong_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    return True, ""


# ── Public API ───────────────────────────────────────────────────────────────

def get_user(email):
    with _lock:
        db = _load_db()
        user = db["users"].get(email.strip().lower())
        if user is None:
            return None
        s = user.get("settings", {})
        s.setdefault("check_interval_minutes", 60)
        s.setdefault("missed_check_grace_minutes", 10)
        ms = user.setdefault("mail_settings", {})
        ms.setdefault("mail_sender", "")
        ms.setdefault("mail_smtp_password", "")
        ms.setdefault("mail_recipient", "")
        ms.setdefault("smtp_server", "")
        ms.setdefault("smtp_port", 587)
        ms.setdefault("smtp_security", "TLS")
        # Role is derived, never stored -- attach for template convenience.
        user["role"] = get_role_for_email(user.get("email", email))
        return user


def all_users():
    with _lock:
        db = _load_db()
        return dict(db["users"])


def register_user(email, password):
    """Create a new account. Intended for admin use via create_user.py."""
    email = email.strip().lower()

    if not is_valid_email(email):
        return False, "Please provide a valid email address."

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

    return True, f"Account created for {email}."


def verify_login(email, password):
    email = email.strip().lower()
    user = get_user(email)
    if user is None:
        return False, "No account found with that email address."
    if not check_password_hash(user["password_hash"], password):
        return False, "Incorrect password."
    return True, "Login successful."


def change_password(email, current_password, new_password):
    email = email.strip().lower()
    ok_login, msg = verify_login(email, current_password)
    if not ok_login:
        return False, f"Current password is incorrect."
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
    email = email.strip().lower()
    allowed_keys = {
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
                try:
                    val = int(val)
                except (TypeError, ValueError):
                    continue
                current[key] = val
        _save_db(db)
    return True, "Settings saved."


def get_user_ips(email):
    user = get_user(email)
    return list(user["ips"]) if user else []


def add_user_ip(email, ip):
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
    import ipaddress as _ip
    email = email.strip().lower()
    added, skipped = [], []
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
    user = get_user(email)
    if user is None:
        return {"last_success_at": None, "last_success_iso": None, "last_alert_sent_for": None}
    return dict(user.get("scheduler_state", {}))


def save_user_scheduler_state(email, state):
    email = email.strip().lower()
    with _lock:
        db = _load_db()
        if email not in db["users"]:
            return
        db["users"][email]["scheduler_state"] = state
        _save_db(db)


# -- Admin-only helpers --------------------------------------------------------
# These are only ever called from routes guarded by an admin_required decorator
# in app.py, never exposed to regular users.

def list_users_summary():
    """Return a list of all accounts with display-safe fields only
    (no password hashes, no SMTP password). Sorted with admins first,
    then by email."""
    with _lock:
        db = _load_db()
        users = db["users"]
    summary = []
    for email, u in users.items():
        ms = u.get("mail_settings", {}) or {}
        configured = all(
            (ms.get(k) or "").strip() if isinstance(ms.get(k), str) else bool(ms.get(k))
            for k in ("mail_sender", "mail_smtp_password", "mail_recipient", "smtp_server")
        )
        summary.append({
            "email": email,
            "role": get_role_for_email(email),
            "ip_count": len(u.get("ips", [])),
            "last_success_at": (u.get("scheduler_state", {}) or {}).get("last_success_at") or "Never",
            "check_interval_minutes": (u.get("settings", {}) or {}).get("check_interval_minutes", 60),
            "mail_configured": configured,
            "mail_recipient": ms.get("mail_recipient", ""),
        })
    summary.sort(key=lambda r: (r["role"] != "admin", r["email"]))
    return summary


def get_user_mail_settings(target_email):
    """Admin-only read of a specific user's mail/SMTP settings, including
    the SMTP password (needed to pre-fill the edit form). Never call this
    from a context a non-admin can reach."""
    target_email = target_email.strip().lower()
    with _lock:
        db = _load_db()
        user = db["users"].get(target_email)
        if user is None:
            return None
        ms = user.setdefault("mail_settings", {})
        ms.setdefault("mail_sender", "")
        ms.setdefault("mail_smtp_password", "")
        ms.setdefault("mail_recipient", "")
        ms.setdefault("smtp_server", "")
        ms.setdefault("smtp_port", 587)
        ms.setdefault("smtp_security", "TLS")
        return dict(ms)


def admin_save_user_mail_settings(target_email, mail_settings):
    """Admin-only write of a specific user's mail/SMTP settings. Each user
    can have a completely different sender/recipient/SMTP server, so the
    scheduler emails that user's own report using their own configuration."""
    target_email = target_email.strip().lower()
    allowed_keys = {
        "mail_sender", "mail_smtp_password", "mail_recipient",
        "smtp_server", "smtp_port", "smtp_security",
    }
    with _lock:
        db = _load_db()
        if target_email not in db["users"]:
            return False, "User not found."
        current = db["users"][target_email].setdefault("mail_settings", {})
        for key in allowed_keys:
            if key in mail_settings:
                val = mail_settings[key]
                if key == "smtp_port":
                    try:
                        val = int(val)
                    except (TypeError, ValueError):
                        continue
                elif isinstance(val, str):
                    val = val.strip()
                current[key] = val
        _save_db(db)
    return True, f"Email configuration saved for {target_email}."


def admin_create_user(email, password):
    """Admin-initiated account creation. Thin wrapper around register_user
    kept separate so the call site in app.py reads clearly as an admin action."""
    return register_user(email, password)


def admin_reset_password(target_email, new_password):
    """Let an admin set a new password for any user (e.g. when a user
    forgot theirs), bypassing the current-password check."""
    target_email = target_email.strip().lower()
    ok_strength, msg = is_strong_password(new_password)
    if not ok_strength:
        return False, msg
    with _lock:
        db = _load_db()
        if target_email not in db["users"]:
            return False, "User not found."
        db["users"][target_email]["password_hash"] = generate_password_hash(new_password)
        _save_db(db)
    return True, f"Password reset for {target_email}."


def admin_delete_user(target_email, requesting_admin_email):
    """Remove a user account entirely. Admins cannot delete their own
    account through this path to avoid accidental lockout."""
    target_email = target_email.strip().lower()
    if target_email == requesting_admin_email.strip().lower():
        return False, "You can't delete your own account while signed in."
    with _lock:
        db = _load_db()
        if target_email not in db["users"]:
            return False, "User not found."
        del db["users"][target_email]
        _save_db(db)
    return True, f"Account for {target_email} removed."
