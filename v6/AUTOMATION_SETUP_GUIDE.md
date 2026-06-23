# Automated Hourly Check + Email Reports - Setup Guide

## What this adds

The app now checks every IP in `uploads/IP.txt` automatically, once an
hour, while it's running - no manual clicking needed. After each check:

- **An email is sent every hour, always** - a "Blocked Report" with a CSV
  attached covering every IP that was flagged Blocked by at least one
  vendor that run (and a short "all clear" summary if nothing was
  blocked).
- **If the hourly check doesn't happen on time** (app crashed, server
  down, etc.), a separate alert email is sent once, warning that the
  scheduled check was missed.

This runs *inside* the same Flask app - no separate program, cron job,
or paid service. It uses your own free Gmail account to send mail.

---

## 1. One-time setup: get a Gmail "App Password"

You cannot use your normal Gmail password for this - Google requires a
separate 16-character "App Password" for apps like this one.

1. Go to your Google Account → Security:
   https://myaccount.google.com/security
2. Turn on **2-Step Verification** if it isn't already on (required
   before App Passwords are available).
3. Go to: https://myaccount.google.com/apppasswords
4. Under "Select app" choose **Mail**. Under "Select device" choose
   **Other**, and name it something like `IP Checker`.
5. Click **Generate**. Google shows a 16-character password like:
   `abcd efgh ijkl mnop`
6. Copy it **without spaces**: `abcdefghijklmnop`

You can use a dedicated Gmail account just for this app if you'd
rather not use your personal one.

---

## 2. Fill in your `.env` file

In the project folder, open `.env` (already created for you, sitting
next to `app.py`) and replace the placeholder values:

```env
MAIL_SENDER=your_email@gmail.com
MAIL_APP_PASSWORD=abcdefghijklmnop
MAIL_RECIPIENT=where_you_want_reports@gmail.com

SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587

CHECK_INTERVAL_MINUTES=60
MISSED_CHECK_GRACE_MINUTES=10
```

- `MAIL_SENDER` - the Gmail address you generated the App Password for.
- `MAIL_APP_PASSWORD` - the 16-character App Password (no spaces).
- `MAIL_RECIPIENT` - where you want the reports/alerts delivered. Can
  be the same address as `MAIL_SENDER`, or a different inbox.
- `CHECK_INTERVAL_MINUTES` - how often the automated check runs.
  Defaults to 60 (every hour), change if you want a different interval.
- `MISSED_CHECK_GRACE_MINUTES` - how much extra time is allowed before
  a "missed check" alert fires. Defaults to 10, meaning if no
  successful run happens within 70 minutes (60 + 10), you get an alert.

**Never share or commit your real `.env` file** - it has your
password in it. `.gitignore` already excludes it. `.env.example` (safe,
no real secrets) is there for reference/sharing.

---

## 3. Install the two new dependencies

```bash
pip install -r requirements.txt
```

This adds `APScheduler` (runs the hourly job in the background) and
`python-dotenv` (loads your `.env` file) on top of what was already
required.

---

## 4. Run the app like normal

```bash
python app.py
```

That's it - as soon as the app starts:
- It runs the IP check **immediately once** (so you don't have to wait
  an hour to see if it's working).
- Then automatically every `CHECK_INTERVAL_MINUTES` after that, for as
  long as the app keeps running.
- A watchdog check runs every few minutes in the background to make
  sure the hourly job hasn't silently stopped happening.

**Important:** the app needs to be left running continuously (e.g. on
a server, or a PC that stays on) for the hourly check to keep
happening. If you stop the app, the automated checks stop too - the
website itself (single-IP search, manual batch button, etc.) still
needs you to start it again to use those, same as before.

---

## 5. Where to see it's working

On the homepage, under "Analyze IPs from File", there's now a small
**"Automated Hourly Check"** box showing:
- **Last successful run** - when the automated check last completed.
- **Next check around** - roughly when the next one will fire.

Check your inbox (`MAIL_RECIPIENT`) for the hourly report email after
the app has been running a few minutes.

---

## What the emails look like

### Hourly report (always sent)
**Subject:** `IP Reputation Checker - Hourly Report (2026-06-19 14:00)`

```
Automated IP Reputation Check
Run time: 2026-06-19 14:00
IPs checked: 7
IPs with at least one Blocked vendor: 2

2 of 7 IP(s) were flagged as Blocked by at least one vendor this run.

Full per-vendor blocked details are attached as a CSV.
```
(CSV attached with the same columns as the existing "Download Blocked
Report" button: Date of Analyzing the IP, IP, Blocked Vendor Name,
Status, Reason, Last Reported Date, Total Reports.)

### Missed-check alert (only if something's wrong)
**Subject:** `ALERT: IP Reputation Checker - Hourly Check Missed`

```
The automated hourly IP check has NOT run successfully on schedule.

Last successful run: 2026-06-19 13:00
Time since last successful run: 75 minute(s)

Please check that the application is still running and that the
network/API keys are working correctly.
```

This alert only sends **once** per missed period - it won't spam your
inbox every few minutes for the same outage. Once the check
successfully runs again, the alert "resets" and is ready to fire again
if a future check is missed.

---

## Troubleshooting

**"SMTP authentication failed" in the console logs:**
Double-check `MAIL_APP_PASSWORD` - it must be the 16-character App
Password from Google, not your normal Gmail login password. Also
confirm 2-Step Verification is enabled on that Google account (App
Passwords don't work without it).

**No emails arriving at all, no errors in console either:**
Check your spam folder. Gmail-to-Gmail mail from a brand-new sending
pattern can occasionally land there the first few times.

**Status panel says "Never run yet":**
The app hasn't completed its first automated run since it started.
Wait a minute after starting the app and refresh the homepage.

**I changed `.env` while the app was already running:**
`.env` is only read when the app starts. Restart the app for changes
to take effect.

---

## Files added/changed for this feature

| File | What changed |
|---|---|
| `services/mailer.py` | **New.** Sends the two email types via Gmail SMTP. |
| `services/scheduler.py` | **New.** Runs the hourly job + watchdog in the background. |
| `.env` / `.env.example` | **New.** Email credentials and timing settings. |
| `.gitignore` | **New.** Keeps `.env` out of version control. |
| `requirements.txt` | Added `APScheduler` and `python-dotenv`. |
| `app.py` | Starts the scheduler on launch; the blocked-report-building logic used by the existing "Download Blocked Report" button was split into reusable functions so the scheduler can call the same logic without duplicating it. The button's behavior and output are unchanged. |
| `templates/index.html` | Added a small "Automated Hourly Check" status box (last run / next run). No existing buttons or forms were changed. |
| `static/css/style.css` | Added styling for the new status box only. |

Nothing about the existing single-IP search, batch-from-file button,
vendor-details page, or manual CSV downloads was changed in behavior -
they all work exactly as before.
