# IP Threatscope – Setup Guide

## Installation

```bash
pip install -r requirements.txt
python app.py
```

Then open **http://localhost:5000** in your browser.

---

## First Use

1. Click **Create one** on the login page to register with your Gmail address.
2. After logging in, go to **⚙ Settings** (top-right navbar).
3. **Add your IPs** – one at a time, or paste a block of IPs (one per line).
4. **Configure mail** – enter your Gmail sender address, a Gmail App Password
   (not your regular Gmail password – get one at
   https://myaccount.google.com/apppasswords), and the recipient address.
5. Set your preferred **check interval** (e.g. 60 = every hour).

---

## What each setting does

| Setting | Description |
|---|---|
| Sender Gmail | The Gmail account that sends the automated report emails |
| Gmail App Password | 16-character App Password (2FA must be enabled on the Gmail account) |
| Recipient Email | Where the reports land (can be any email, not just Gmail) |
| SMTP Server / Port | Leave as `smtp.gmail.com` / `587` unless you use a different mail provider |
| Check Interval (min) | How often the background job re-scans all your IPs and emails a report |
| Missed-Check Grace (min) | Extra buffer before a "missed check" alert is sent |

---

## Multiple Users

Each user who registers gets:
- Their own **IP list** (no sharing between accounts)
- Their own **mail credentials** and **scheduler interval**
- Their own **per-session scan results** (two users browsing at the same time see only their own data)

All user data is stored in `data/users.json`.  
**Back this file up** – it contains all accounts and settings.

---

## Changing Your Password

Go to **🔑 Change Password** in the top-right navbar at any time.
The new password replaces the old one in `data/users.json` immediately.

---

## Running in Production

For a proper deployment (instead of Flask's dev server), use Gunicorn:

```bash
pip install gunicorn
gunicorn -w 1 -b 0.0.0.0:5000 app:app
```

> **Note:** Use a single worker (`-w 1`). The background scheduler runs inside
> the Flask process; multiple workers would run duplicate schedulers and send
> duplicate emails.

Change `app.secret_key` in `app.py` to a random 32-character string before
going live.
