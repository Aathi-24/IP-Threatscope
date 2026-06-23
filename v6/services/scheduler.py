"""
Per-user background scheduler for the IP Reputation Checker.

A single "master tick" job runs every minute. On each tick it iterates
over every registered user, checks if their scheduled check is due
(based on their own check_interval_minutes setting), and if so, runs
their IP list through all vendor APIs and emails them the blocked report.

A watchdog also runs every few minutes to alert users whose checks have
gone overdue.

Scheduler state (last_success_at, next_alert tracking etc.) is stored
per-user in data/users.json via auth.py, NOT in a separate
scheduler_state.json, so there's one source of truth.
"""

import os
import threading
from datetime import datetime, timedelta
from io import StringIO

from apscheduler.schedulers.background import BackgroundScheduler

from services.mailer import send_blocked_report_email, send_missed_check_alert

_scheduler = None
_lock = threading.Lock()


def get_scheduler_status_for_user(email):
    """Return a small status dict for the current user's last/next run.
    Called by app.py to populate the dashboard's scheduler panel.
    """
    from services.auth import get_user_scheduler_state, get_user
    user = get_user(email)
    if user is None:
        return {"last_success_at": "Never", "next_check_eta": "N/A",
                "interval_minutes": 60}

    interval = user["settings"].get("check_interval_minutes", 60)
    state = user.get("scheduler_state", {})
    last_success_iso = state.get("last_success_iso")

    next_check_eta = "N/A"
    if last_success_iso:
        try:
            last_dt = datetime.fromisoformat(last_success_iso)
            next_dt = last_dt + timedelta(minutes=int(interval))
            next_check_eta = next_dt.strftime("%Y-%m-%d %H:%M")
        except (ValueError, TypeError):
            pass

    return {
        "last_success_at": state.get("last_success_at") or "Never run yet",
        "next_check_eta": next_check_eta,
        "interval_minutes": interval,
    }


def _is_email_rate_limited(email, user):
    """Check if an email was sent to this user within the last hour."""
    from services.auth import get_user_scheduler_state
    state = user.get("scheduler_state", {})
    last_email_iso = state.get("last_email_sent_at")
    
    if not last_email_iso:
        return False  # No email sent yet, not rate limited
    
    try:
        last_email_dt = datetime.fromisoformat(last_email_iso)
        minutes_since = (datetime.now() - last_email_dt).total_seconds() / 60
        return minutes_since < 60  # Rate limited if email sent within last 60 minutes
    except (ValueError, TypeError):
        return False


def _run_check_for_user(email, user, process_single_ip, skip_rate_limit=False):
    """Run the full scan + email cycle for one user."""
    import pandas as pd
    from services.auth import save_user_scheduler_state, get_user_scheduler_state

    run_time = datetime.now().strftime("%Y-%m-%d %H:%M")
    ips = user.get("ips", [])
    settings = user.get("settings", {})

    if not ips:
        return  # nothing to scan

    # Check if email rate limited (one email per hour), unless skipped (e.g., "Run Now")
    if not skip_rate_limit and _is_email_rate_limited(email, user):
        return  # Email sent recently, skip this run

    # Build report rows
    report_rows = []
    blocked_ip_count = 0

    for ip in ips:
        try:
            data = process_single_ip(ip)
        except Exception:
            continue
        analyzed_at = data.get("analyzed_at", run_time)
        ip_blocked = False
        for row in data.get("results", []):
            if row.get("Blocked") == "Blocked":
                ip_blocked = True
                report_rows.append({
                    "Date of Analyzing the IP": analyzed_at,
                    "IP": ip,
                    "Blocked Vendor Name": row.get("Vendor", "N/A"),
                    "Status": "Blocked",
                    "Reason": row.get("Reason", "Nil"),
                    "Last Reported Date": row.get("Last_Reported", "Nil"),
                    "Total Reports": row.get("Total_Reports", "N/A"),
                })
        if ip_blocked:
            blocked_ip_count += 1

    # Build CSV
    columns = [
        "Date of Analyzing the IP", "IP", "Blocked Vendor Name",
        "Status", "Reason", "Last Reported Date", "Total Reports",
    ]
    df = pd.DataFrame(report_rows, columns=columns)
    buf = StringIO()
    df.to_csv(buf, index=False)

    filename = f"Scheduled_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
    summary = {
        "run_time": run_time,
        "total_ips": len(ips),
        "blocked_ips": blocked_ip_count,
    }

    send_blocked_report_email(settings, buf.getvalue(), filename, summary)

    # Update scheduler state
    state = get_user_scheduler_state(email)
    state["last_success_at"] = run_time
    state["last_success_iso"] = datetime.now().isoformat()
    state["last_email_sent_at"] = datetime.now().isoformat()
    state["last_alert_sent_for"] = None
    save_user_scheduler_state(email, state)


def _master_tick(process_single_ip):
    """Run once per minute. Checks every user to see if their scheduled
    check is due or their watchdog should fire."""
    from services.auth import all_users, get_user_scheduler_state, save_user_scheduler_state

    now = datetime.now()

    for email, user in all_users().items():
        try:
            settings = user.get("settings", {})
            interval = int(settings.get("check_interval_minutes", 60))
            grace    = int(settings.get("missed_check_grace_minutes", 10))
            state    = user.get("scheduler_state", {})
            last_iso = state.get("last_success_iso")

            # ---- Due check ----
            if last_iso is None:
                # Never run before - run now if the user has IPs and settings
                if user.get("ips") and settings.get("mail_app_password", "").strip():
                    _run_check_for_user(email, user, process_single_ip)
            else:
                try:
                    last_dt = datetime.fromisoformat(last_iso)
                except ValueError:
                    continue
                if (now - last_dt).total_seconds() / 60 >= interval:
                    _run_check_for_user(email, user, process_single_ip)

            # ---- Watchdog ----
            if last_iso is None:
                continue
            try:
                last_dt = datetime.fromisoformat(last_iso)
            except ValueError:
                continue
            minutes_since = (now - last_dt).total_seconds() / 60
            threshold = interval + grace
            if minutes_since > threshold:
                last_alert = state.get("last_alert_sent_for")
                # Also check rate limit: no email within last 60 minutes
                if last_alert != last_iso and not _is_email_rate_limited(email, user):
                    send_missed_check_alert(
                        settings,
                        state.get("last_success_at") or "never",
                        round(minutes_since),
                    )
                    state["last_alert_sent_for"] = last_iso
                    state["last_email_sent_at"] = datetime.now().isoformat()
                    save_user_scheduler_state(email, state)

        except Exception:
            # Never let one user's error crash the whole tick
            pass


def start_scheduler(process_single_ip):
    """Start the background scheduler. Safe to call multiple times."""
    global _scheduler
    with _lock:
        if _scheduler is not None:
            return _scheduler

        _scheduler = BackgroundScheduler(daemon=True)
        _scheduler.add_job(
            func=_master_tick,
            args=(process_single_ip,),
            trigger="interval",
            minutes=1,
            id="master_tick",
            next_run_time=datetime.now(),
            max_instances=1,
            coalesce=True,
        )
        _scheduler.start()
        return _scheduler
