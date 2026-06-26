"""
Email sending for IP Threatscope's automated scheduled checks.

Each user has their own mail_settings (sender, SMTP password, recipient,
server, port, security mode), managed only by admins via the Admin
Console -> Email Configuration screen. The scheduler passes that user's
own settings dict in here so their report goes out from their own
configured account to their own configured recipient.

Supports any SMTP server with four security modes:
  TLS   - STARTTLS (most common, port 587)
  SSL   - SMTP_SSL (legacy, port 465)
  AUTO  - tries TLS first, falls back to SSL
  NONE  - plain SMTP, no encryption (port 25; not recommended)
"""

import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication


def mail_is_configured(settings):
    valid, _ = _settings_are_valid(settings or {})
    return valid


def _settings_are_valid(settings):
    missing = [
        k for k in ("mail_sender", "mail_smtp_password", "mail_recipient", "smtp_server")
        if not (settings.get(k) or "").strip()
    ]
    return len(missing) == 0, missing


def _send_email(settings, subject, body_text,
                attachment_bytes=None, attachment_filename=None):
    """Send an email using the given user's SMTP settings.

    Returns (success: bool, message: str). Never raises.
    """
    settings = settings or {}
    valid, missing = _settings_are_valid(settings)
    if not valid:
        return False, (
            f"Email not sent - missing email configuration for: {', '.join(missing)}. "
            f"Ask an administrator to set it up in Admin Console -> Email Configuration."
        )

    sender    = settings["mail_sender"].strip()
    password  = settings["mail_smtp_password"].strip()
    recipient = settings["mail_recipient"].strip()
    server    = settings["smtp_server"].strip()
    port      = int(settings.get("smtp_port", 587))
    security  = (settings.get("smtp_security") or "TLS").upper().strip()

    msg = MIMEMultipart()
    msg["From"]    = sender
    msg["To"]      = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body_text, "plain"))

    if attachment_bytes is not None and attachment_filename:
        part = MIMEApplication(attachment_bytes, Name=attachment_filename)
        part["Content-Disposition"] = f'attachment; filename="{attachment_filename}"'
        msg.attach(part)

    raw = msg.as_string()

    try:
        if security == "SSL":
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(server, port, context=ctx, timeout=30) as srv:
                srv.login(sender, password)
                srv.sendmail(sender, recipient, raw)

        elif security == "TLS":
            with smtplib.SMTP(server, port, timeout=30) as srv:
                srv.ehlo()
                srv.starttls(context=ssl.create_default_context())
                srv.ehlo()
                srv.login(sender, password)
                srv.sendmail(sender, recipient, raw)

        elif security == "NONE":
            with smtplib.SMTP(server, port, timeout=30) as srv:
                if password:
                    srv.login(sender, password)
                srv.sendmail(sender, recipient, raw)

        else:  # AUTO - try TLS first, fall back to SSL
            try:
                with smtplib.SMTP(server, port, timeout=30) as srv:
                    srv.ehlo()
                    srv.starttls(context=ssl.create_default_context())
                    srv.ehlo()
                    srv.login(sender, password)
                    srv.sendmail(sender, recipient, raw)
            except Exception:
                ctx = ssl.create_default_context()
                with smtplib.SMTP_SSL(server, port, context=ctx, timeout=30) as srv:
                    srv.login(sender, password)
                    srv.sendmail(sender, recipient, raw)

        return True, "Email sent successfully."

    except smtplib.SMTPAuthenticationError:
        return False, (
            "SMTP authentication failed. Ask an administrator to check the "
            "sender email and SMTP password in this user's Email Configuration."
        )
    except smtplib.SMTPConnectError as e:
        return False, f"Could not connect to {server}:{port} - {e}"
    except Exception as e:
        return False, f"Failed to send email: {e}"


def send_blocked_report_email(settings, csv_text, filename, summary):
    """Send the scheduled blocked-IP report with the CSV attached, using
    the given user's own mail_settings."""
    subject = f"IP Threatscope - Scheduled Report ({summary.get('run_time', '')})"

    if summary.get("blocked_ips", 0) > 0:
        headline = (
            f"{summary['blocked_ips']} of {summary['total_ips']} IP(s) "
            f"were flagged as Blocked by at least one vendor."
        )
    else:
        headline = (
            f"All clear - none of the {summary['total_ips']} IP(s) checked "
            f"were flagged as Blocked by any vendor."
        )

    body = (
        f"IP Threatscope - Automated Threat Intelligence Report\n"
        f"{'='*52}\n"
        f"Run time     : {summary.get('run_time', 'N/A')}\n"
        f"IPs checked  : {summary.get('total_ips', 'N/A')}\n"
        f"IPs blocked  : {summary.get('blocked_ips', 'N/A')}\n\n"
        f"{headline}\n\n"
        f"Full per-vendor blocked details are attached as a CSV.\n\n"
        f"-\nIP Threatscope by NAKOA Technologies\n"
        f"info@nakoatech.com | +91 90809 95043\n"
    )

    return _send_email(
        settings, subject, body,
        attachment_bytes=csv_text.encode("utf-8"),
        attachment_filename=filename,
    )


def send_missed_check_alert(settings, last_success_time, minutes_since):
    """Send a watchdog alert when a scheduled check is overdue, using the
    given user's own mail_settings."""
    subject = "ALERT: IP Threatscope - Scheduled Check Missed"
    body = (
        f"IP Threatscope - Missed Check Alert\n"
        f"{'='*36}\n"
        f"Last successful run  : {last_success_time or 'never'}\n"
        f"Minutes since last run: {minutes_since}\n\n"
        f"The automated IP reputation check has not run on schedule.\n"
        f"Please verify that the application is running and that the\n"
        f"SMTP credentials and network connectivity configured for this\n"
        f"account are correct.\n\n"
        f"-\nIP Threatscope by NAKOA Technologies\n"
    )
    return _send_email(settings, subject, body)
