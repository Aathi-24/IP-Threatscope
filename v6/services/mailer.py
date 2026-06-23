"""
Email sending for the IP Reputation Checker's automated hourly check.

Each user provides their own mail credentials in their account settings,
so send_blocked_report_email() and send_missed_check_alert() now accept
a 'settings' dict instead of reading from a shared .env file.

The settings dict shape matches what auth.py stores under user["settings"]:
{
    "mail_sender":      "sender@gmail.com",
    "mail_app_password": "xxxx xxxx xxxx xxxx",
    "mail_recipient":   "recipient@example.com",
    "smtp_server":      "smtp.gmail.com",     # optional, defaults to gmail
    "smtp_port":        587,                  # optional
}
"""

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication


def _settings_are_valid(settings):
    missing = [
        key for key in ("mail_sender", "mail_app_password", "mail_recipient")
        if not settings.get(key, "").strip()
    ]
    return len(missing) == 0, missing


def _send_email(settings, subject, body_text,
                attachment_bytes=None, attachment_filename=None):
    """Low-level send routine.

    Returns (success: bool, message: str) - never raises so callers
    (scheduler jobs) can log failures without crashing.
    """
    valid, missing = _settings_are_valid(settings)
    if not valid:
        return False, (
            f"Email not sent - missing values for: {', '.join(missing)}. "
            f"Fill them in under Account Settings."
        )

    sender     = settings["mail_sender"].strip()
    password   = settings["mail_app_password"].strip()
    recipient  = settings["mail_recipient"].strip()
    server     = settings.get("smtp_server", "smtp.gmail.com")
    port       = int(settings.get("smtp_port", 587))

    msg = MIMEMultipart()
    msg["From"]    = sender
    msg["To"]      = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body_text, "plain"))

    if attachment_bytes is not None and attachment_filename:
        part = MIMEApplication(attachment_bytes, Name=attachment_filename)
        part["Content-Disposition"] = f'attachment; filename="{attachment_filename}"'
        msg.attach(part)

    try:
        with smtplib.SMTP(server, port, timeout=30) as srv:
            srv.starttls()
            srv.login(sender, password)
            srv.sendmail(sender, recipient, msg.as_string())
        return True, "Email sent successfully."
    except smtplib.SMTPAuthenticationError:
        return False, (
            "SMTP authentication failed. Double-check your Gmail address "
            "and App Password in Account Settings (use an App Password, "
            "not your regular Gmail password)."
        )
    except Exception as e:
        return False, f"Failed to send email: {e}"


def send_blocked_report_email(settings, csv_text, filename, summary):
    """Send the scheduled blocked-report email with the CSV attached."""
    subject = (
        f"IP Reputation Checker - Report ({summary.get('run_time', '')})"
    )

    if summary.get("blocked_ips", 0) > 0:
        headline = (
            f"{summary['blocked_ips']} of {summary['total_ips']} IP(s) "
            f"were flagged as Blocked by at least one vendor this run."
        )
    else:
        headline = (
            f"All clear - none of the {summary['total_ips']} IP(s) checked "
            f"were flagged as Blocked by any vendor this run."
        )

    body = (
        f"Automated IP Reputation Check\n"
        f"Run time:  {summary.get('run_time', 'N/A')}\n"
        f"IPs checked: {summary.get('total_ips', 'N/A')}\n"
        f"IPs with at least one Blocked vendor: {summary.get('blocked_ips', 'N/A')}\n\n"
        f"{headline}\n\n"
        f"Full per-vendor blocked details are attached as a CSV.\n"
    )

    return _send_email(
        settings, subject, body,
        attachment_bytes=csv_text.encode("utf-8"),
        attachment_filename=filename,
    )


def send_missed_check_alert(settings, last_success_time, minutes_since):
    """Send the watchdog alert when a scheduled check is overdue."""
    subject = "ALERT: IP Reputation Checker - Scheduled Check Missed"
    body = (
        f"The automated IP check has NOT run successfully on schedule.\n\n"
        f"Last successful run: {last_success_time or 'never'}\n"
        f"Time since last successful run: {minutes_since} minute(s)\n\n"
        f"Please check that the application is still running and that "
        f"your API keys and network connectivity are working correctly.\n"
    )
    return _send_email(settings, subject, body)
