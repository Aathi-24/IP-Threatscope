# IP Threatscope — Setup & Admin Guide

## Quick Start

```bash
pip install -r requirements.txt
cp .env.example .env   # then fill in real values, see below
python app.py
```

Open **http://localhost:5000** in a browser. You'll see the public landing page.

---

## Roles: Admin vs. User

There is no separate "make this person an admin" toggle. Role is decided
purely by **email domain** at login time:

- Any account ending in **`@nakoatech.com`** signs in to the **Admin Console**
  (`/admin`) — manage user accounts, reset forgotten passwords, and see
  whether email delivery is configured.
- Every other domain signs in to the regular **user workspace** — scan IPs,
  manage their own IP watchlist, adjust their scheduler timing, and change
  their own password.

Each side is walled off from the other: a regular user can't reach `/admin`,
and an admin is redirected away from the IP-scanning screens to their own
dashboard.

---

## Creating User Accounts

**From the Admin Console (recommended):** sign in with a `@nakoatech.com`
account, then go to **Manage Users** to create accounts, reset passwords,
or remove users — no server access needed.

**From the command line** (useful for bootstrapping the first admin account):

```bash
python3 create_user.py user@company.com TemporaryPassword123!
```

The account's role is inferred automatically from the domain you give it.
Email the credentials to the person and ask them to change their password
immediately after first login.

---

## Email / SMTP Configuration (.env only)

Email/SMTP settings are **not** configurable from any screen in the app —
not by users, not by admins. They live exclusively in the server's `.env`
file, so they're never stored in `data/users.json` and never rendered in
any template.

Copy `.env.example` to `.env` and fill in:

| Variable | Description |
|---|---|
| `MAIL_SENDER` | The address emails are sent *from* |
| `MAIL_SMTP_PASSWORD` | Password for authenticating with the SMTP server |
| `MAIL_RECIPIENT` | Where blocked-IP reports are delivered |
| `SMTP_SERVER` | e.g. `smtp.office365.com`, `mail.company.com` |
| `SMTP_PORT` | 587 (TLS/STARTTLS) · 465 (SSL) · 25 (plain) |
| `SMTP_SECURITY` | `TLS`, `SSL`, `AUTO`, or `NONE` |

Restart the app after changing `.env`. Admins can check whether delivery is
configured (status only, no values) under **Admin Console → Email Configuration**.

### Common SMTP references

| Provider | Server | Port | Security |
|---|---|---|---|
| Microsoft 365 | smtp.office365.com | 587 | TLS |
| Google Workspace | smtp.gmail.com | 587 | TLS |
| Exchange On-Prem | your-exchange-server | 587 | TLS |
| Generic SSL | your-server | 465 | SSL |

Each user's own **Check Interval** and **Missed-Check Grace** (in minutes)
are still configured per-account in **Settings → Scheduler**.

---

## Changing Password

- Regular users: **Settings → Security** tab.
- Admins: **Admin Console → My Password**.
- Forgot a user's password? An admin can reset it from **Manage Users**
  without needing the old one.

---

## Production Deployment

```bash
pip install gunicorn
gunicorn -w 1 -b 0.0.0.0:5000 app:app
```

> **Use a single worker** (`-w 1`). The background scheduler runs inside the
> Flask process; multiple workers would create duplicate scheduler jobs.

Set `FLASK_SECRET_KEY` in `.env` to a random 32+ character string before
going live (generate one with `python3 -c "import secrets; print(secrets.token_hex(32))"`).

---

## Contact / Support

**NAKOA Technologies**
- Email: info@nakoatech.com
- Phone: +91 90809 95043
- Address: 2/5, Vilankurichi Road, Kumutham Nagar, Cheran Managar, Coimbatore, India 641035
