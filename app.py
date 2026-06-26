from functools import wraps
from io import StringIO
from flask import (Flask, render_template, request, Response,
                   flash, redirect, url_for, session)
from dotenv import load_dotenv
from services.main_file import abuseipdb, virustotal
from services.extra_vendors import greynoise, ipqualityscore, shodan_internetdb
from services.scheduler import start_scheduler, get_scheduler_status_for_user, _run_check_for_user
from services.mailer import mail_is_configured
from services.auth import (
    verify_login, change_password,
    save_user_settings, get_user_ips, add_user_ip, add_user_ips_bulk,
    remove_user_ip, get_user, get_user_scheduler_state, save_user_scheduler_state,
    get_role_for_email, is_admin_email, list_users_summary,
    admin_create_user, admin_reset_password, admin_delete_user,
    get_user_mail_settings, admin_save_user_mail_settings,
)
from ipwhois import IPWhois
import pandas as pd
import ipaddress
from datetime import datetime
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "").strip() or "ipt_secret_key_change_in_production_32chars"

# ── Per-user in-memory scan state ──────────────────────────────────────────
_user_state: dict = {}

def _get_state(email: str) -> dict:
    if email not in _user_state:
        _user_state[email] = {
            "latest_results": [], "latest_ip": None,
            "latest_analyzed_at": None, "batch_ips": [],
            "batch_results": {}, "current_batch_index": 0,
            "scan_history": [],
        }
    return _user_state[email]

def _add_to_history(email, ip, data):
    st = _get_state(email)
    entry = {
        "ip": ip, "verdict": data.get("verdict", "Safe"),
        "blocked": data.get("blocked", 0), "total": data.get("total", 0),
        "analyzed_at": data.get("analyzed_at", datetime.now().strftime("%Y-%m-%d %H:%M")),
    }
    h = st["scan_history"]
    if h and h[0]["ip"] == ip:
        h[0] = entry
    else:
        h.insert(0, entry)
    st["scan_history"] = h[:10]

# ── Auth decorators ──────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_email" not in session:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Only accounts on the nakoatech.com domain may pass."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_email" not in session:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login"))
        if not is_admin_email(session["user_email"]):
            flash("That page is for administrators only.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated

def user_area_required(f):
    """Guards the regular-user workspace. Admins are redirected to their
    own dashboard instead of seeing the end-user IP-scanning screens."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_email" not in session:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login"))
        if is_admin_email(session["user_email"]):
            return redirect(url_for("admin_dashboard"))
        return f(*args, **kwargs)
    return decorated

# ── No-cache headers ────────────────────────────────────────────────────────
@app.after_request
def add_no_cache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# ── IP processing ───────────────────────────────────────────────────────────
def process_single_ip(ip: str) -> dict:
    analyzed_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    try:
        abuse_data = abuseipdb(ip)
        vt_results = virustotal(ip) or []
        extra = []
        if abuse_data:
            extra.append({
                "Vendor": abuse_data.get("Vendor", "AbuseIPDB"),
                "Blocked": abuse_data.get("Blocked", "Safe"),
                "Reason": abuse_data.get("Reason", "Nil"),
                "Total_Reports": abuse_data.get("Total_Reports", "N/A"),
                "Last_Reported": abuse_data.get("Last_Reported", "Nil"),
                "Link": abuse_data.get("Link", f"https://www.abuseipdb.com/check/{ip}"),
            })
        for fn in (greynoise, ipqualityscore, shodan_internetdb):
            row = fn(ip)
            if row:
                extra.append(row)
        results = extra + vt_results
        total   = len(results)
        blocked = sum(1 for r in results if r["Blocked"] == "Blocked")
        if vt_results:
            tr, lr = vt_results[0].get("Total_Reports"), vt_results[0].get("Last_Reported")
        elif abuse_data:
            tr, lr = abuse_data.get("Total_Reports"), abuse_data.get("Last_Reported")
        else:
            tr = lr = "N/A"
        return {
            "results": results, "total": total, "safe": total - blocked,
            "blocked": blocked, "verdict": "Suspicious" if blocked > 0 else "Safe",
            "total_reports": tr, "last_reported": lr,
            "analyzed_at": analyzed_at, "error": None,
        }
    except Exception as e:
        return {
            "results": [], "total": 0, "safe": 0, "blocked": 0,
            "verdict": "Error", "total_reports": "N/A", "last_reported": "N/A",
            "analyzed_at": analyzed_at, "error": str(e),
        }

# ── Context processor ───────────────────────────────────────────────────────
@app.context_processor
def inject_common():
    email = session.get("user_email")
    if not email:
        return {}
    role = get_role_for_email(email)
    if role == "admin":
        return {"active_page": "", "role": role}
    st = _get_state(email)
    try:
        user  = get_user(email)
        sched = get_scheduler_status_for_user(email)
    except Exception:
        user  = {"settings": {}, "ips": [], "mail_settings": {}}
        sched = {"last_success_at": "Never", "next_check_eta": "N/A", "interval_minutes": 0}
    return {
        "user": user, "scan_history": st["scan_history"],
        "scheduler_status": sched, "active_page": "", "role": role,
        "mail_configured": mail_is_configured(user.get("mail_settings", {})),
    }

# ── Landing page (public) ───────────────────────────────────────────────────
@app.route("/")
def index():
    """Public landing page — no login required."""
    if "user_email" in session:
        if is_admin_email(session["user_email"]):
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("dashboard"))
    return render_template("index.html")

# ── Auth routes ─────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_email" in session:
        if is_admin_email(session["user_email"]):
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        ok, msg  = verify_login(email, password)
        if ok:
            session["user_email"] = email
            session["role"]       = get_role_for_email(email)
            if session["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("dashboard"))
        flash(msg, "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("index"))

# ── Dashboard ───────────────────────────────────────────────────────────────
@app.route("/dashboard", methods=["GET", "POST"])
@user_area_required
def dashboard():
    email = session["user_email"]
    st    = _get_state(email)

    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        if not ip:
            flash("Please enter an IP address.", "danger")
            return redirect(url_for("dashboard"))
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            flash("Please enter a valid IPv4 or IPv6 address.", "danger")
            return redirect(url_for("dashboard"))

        data = process_single_ip(ip)
        st["latest_results"]     = data["results"]
        st["latest_ip"]          = ip
        st["latest_analyzed_at"] = data["analyzed_at"]
        st["batch_ips"]          = []
        st["batch_results"]      = {}
        st["current_batch_index"] = 0
        _add_to_history(email, ip, data)

        return render_template(
            "result.html",
            results=data["results"], total=data["total"],
            safe=data["safe"], blocked=data["blocked"],
            ip=ip, verdict=data["verdict"],
            total_reports=data["total_reports"],
            last_reported=data["last_reported"],
            error=data["error"], is_batch=False, batch_info=None,
            active_page="dashboard",
        )

    sched = get_scheduler_status_for_user(email)
    user  = get_user(email)
    return render_template("dashboard.html",
                           user=user, scheduler_status=sched,
                           active_page="dashboard")

# ── Settings ─────────────────────────────────────────────────────────────────
@app.route("/settings", methods=["GET", "POST"])
@user_area_required
def settings():
    email = session["user_email"]

    if request.method == "POST":
        action = request.form.get("action", "")

        if action == "save_settings":
            # Only scheduler timing is editable here. Email/SMTP delivery
            # configuration lives exclusively in the .env file and is
            # never accepted from a form submission.
            new_settings = {
                "check_interval_minutes":   request.form.get("check_interval_minutes", 60),
                "missed_check_grace_minutes": request.form.get("missed_check_grace_minutes", 10),
            }
            ok, msg = save_user_settings(email, new_settings)
            flash(msg, "success" if ok else "danger")

        elif action == "change_password":
            current = request.form.get("current_password", "")
            new     = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            if new != confirm:
                flash("New passwords do not match.", "danger")
            else:
                ok, msg = change_password(email, current, new)
                flash(msg, "success" if ok else "danger")

        elif action == "add_ip":
            ip = request.form.get("new_ip", "").strip()
            ok, msg = add_user_ip(email, ip)
            flash(msg, "success" if ok else "danger")

        elif action == "bulk_add_ips":
            raw = request.form.get("bulk_ips", "")
            added, skipped = add_user_ips_bulk(email, raw)
            if added:
                flash(f"Added {len(added)} IP(s): {', '.join(added)}", "success")
            if skipped:
                flash(f"Skipped {len(skipped)} (duplicate or invalid): {', '.join(skipped)}", "warning")

        elif action == "remove_ip":
            ip = request.form.get("ip_to_remove", "").strip()
            ok, msg = remove_user_ip(email, ip)
            flash(msg, "success" if ok else "danger")

        elif action == "run_now":
            user = get_user(email)
            if not user.get("ips"):
                flash("Your IP list is empty. Add IPs first.", "warning")
            else:
                try:
                    _run_check_for_user(email, user, process_single_ip, skip_rate_limit=True)
                    state = get_user_scheduler_state(email)
                    now_iso = datetime.now().isoformat()
                    state.update({
                        "last_success_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
                        "last_success_iso": now_iso,
                        "last_alert_sent_for": None,
                    })
                    save_user_scheduler_state(email, state)
                    if mail_is_configured(user.get("mail_settings", {})):
                        flash("Check triggered — report will be emailed shortly.", "success")
                    else:
                        flash("Check triggered. Email delivery isn't configured yet, "
                              "so no report email was sent — contact your administrator.", "warning")
                except Exception as e:
                    flash(f"Error running check: {e}", "danger")

        return redirect(url_for("settings"))

    user  = get_user(email)
    sched = get_scheduler_status_for_user(email)
    return render_template("settings.html",
                           user=user, scheduler_status=sched,
                           active_page="settings")

# ── Batch scanning ───────────────────────────────────────────────────────────
@app.route("/run-batch")
@user_area_required
def run_batch():
    email = session["user_email"]
    st    = _get_state(email)
    ips   = get_user_ips(email)
    if not ips:
        flash("Your IP list is empty. Add IPs in Settings first.", "warning")
        return redirect(url_for("settings"))
    st["batch_ips"]           = ips
    st["batch_results"]       = {}
    st["current_batch_index"] = 0
    flash(f"Loaded {len(ips)} IP(s). Scanning now.", "success")
    return redirect(url_for("view_batch_ip", index=0))

@app.route("/batch/<int:index>")
@user_area_required
def view_batch_ip(index):
    email = session["user_email"]
    st    = _get_state(email)
    if not st["batch_ips"] or index < 0 or index >= len(st["batch_ips"]):
        flash("Invalid batch index.", "danger")
        return redirect(url_for("dashboard"))
    st["current_batch_index"] = index
    ip = st["batch_ips"][index]
    if ip not in st["batch_results"]:
        st["batch_results"][ip] = process_single_ip(ip)
    data = st["batch_results"][ip]
    st["latest_results"]     = data["results"]
    st["latest_ip"]          = ip
    st["latest_analyzed_at"] = data["analyzed_at"]
    _add_to_history(email, ip, data)
    batch_info = {
        "current": index + 1, "total": len(st["batch_ips"]),
        "has_next": index < len(st["batch_ips"]) - 1, "has_prev": index > 0,
    }
    return render_template(
        "result.html",
        results=data["results"], total=data["total"],
        safe=data["safe"], blocked=data["blocked"],
        ip=ip, verdict=data["verdict"],
        total_reports=data["total_reports"],
        last_reported=data["last_reported"],
        error=data["error"], is_batch=True, batch_info=batch_info,
        active_page="batch",
    )

# ── Vendor details ───────────────────────────────────────────────────────────
def _get_vendor_rows(email, vendor_name):
    st = _get_state(email)
    rows = []
    if st["batch_ips"]:
        for ip in st["batch_ips"]:
            data = st["batch_results"].get(ip)
            if not data:
                continue
            for row in data["results"]:
                if row.get("Vendor") == vendor_name:
                    rows.append({
                        "ip": ip, "status": row.get("Blocked", "N/A"),
                        "reason": row.get("Reason", "Nil"),
                        "last_reported": row.get("Last_Reported", "Nil"),
                        "total_reports": row.get("Total_Reports", "N/A"),
                    })
                    break
    elif st["latest_ip"] and st["latest_results"]:
        for row in st["latest_results"]:
            if row.get("Vendor") == vendor_name:
                rows.append({
                    "ip": st["latest_ip"], "status": row.get("Blocked", "N/A"),
                    "reason": row.get("Reason", "Nil"),
                    "last_reported": row.get("Last_Reported", "Nil"),
                    "total_reports": row.get("Total_Reports", "N/A"),
                })
                break
    return rows

@app.route("/vendor/<vendor_name>")
@user_area_required
def vendor_details(vendor_name):
    email = session["user_email"]
    rows  = _get_vendor_rows(email, vendor_name)
    if not rows:
        flash(f"No results found for vendor '{vendor_name}'.", "danger")
        return redirect(url_for("dashboard"))
    st = _get_state(email)
    return render_template("vendor_details.html",
                           vendor_name=vendor_name, rows=rows,
                           is_batch=bool(st["batch_ips"]), active_page="")

# ── WHOIS details ────────────────────────────────────────────────────────────
def _whois_lookup(ip):
    try:
        obj    = IPWhois(ip)
        result = obj.lookup_rdap()
        net    = result.get("network", {})
        return {
            "asn": result.get("asn","N/A"), "asn_registry": result.get("asn_registry","N/A"),
            "asn_cidr": result.get("asn_cidr","N/A"), "asn_country_code": result.get("asn_country_code","N/A"),
            "asn_date": result.get("asn_date","N/A"), "asn_description": result.get("asn_description","N/A"),
            "network_name": net.get("name","N/A"), "network_handle": net.get("handle","N/A"),
            "network_type": net.get("type","N/A"), "country": net.get("country","N/A"),
            "cidr": net.get("cidr","N/A"), "start_address": net.get("start_address","N/A"),
            "end_address": net.get("end_address","N/A"),
            "created": (net.get("events",[{}])[0].get("timestamp","N/A") if net.get("events") else "N/A"),
            "remarks": net.get("remarks","N/A"),
        }
    except Exception:
        return {k: "N/A" for k in [
            "asn","asn_registry","asn_cidr","asn_country_code","asn_date","asn_description",
            "network_name","network_handle","network_type","country","cidr",
            "start_address","end_address","created","remarks",
        ]}

@app.route("/details/<ip>")
@user_area_required
def details(ip):
    return render_template("details.html", ip=ip,
                           whois=_whois_lookup(ip),
                           abuse=abuseipdb(ip), active_page="")

# ── CSV downloads ─────────────────────────────────────────────────────────────
@app.route("/download/<ip>")
@user_area_required
def download_csv(ip):
    st  = _get_state(session["user_email"])
    buf = StringIO()
    pd.DataFrame(st["latest_results"]).to_csv(buf, index=False)
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={ip}_results.csv"})

@app.route("/download_blocked_report")
@user_area_required
def download_blocked_report():
    email = session["user_email"]
    st    = _get_state(email)
    cols  = ["Date of Analyzing the IP","IP","Blocked Vendor Name",
             "Status","Reason","Last Reported Date","Total Reports"]
    rows  = []

    if st["batch_ips"]:
        for ip in st["batch_ips"]:
            if ip not in st["batch_results"]:
                st["batch_results"][ip] = process_single_ip(ip)
        for ip in st["batch_ips"]:
            data = st["batch_results"].get(ip)
            if not data:
                continue
            at = data.get("analyzed_at", datetime.now().strftime("%Y-%m-%d %H:%M"))
            for r in data["results"]:
                if r.get("Blocked") == "Blocked":
                    rows.append({"Date of Analyzing the IP": at, "IP": ip,
                                 "Blocked Vendor Name": r.get("Vendor","N/A"),
                                 "Status": "Blocked", "Reason": r.get("Reason","Nil"),
                                 "Last Reported Date": r.get("Last_Reported","Nil"),
                                 "Total Reports": r.get("Total_Reports","N/A")})
        prefix = "Blocked_Report"
    elif st["latest_ip"] and st["latest_results"]:
        at = st["latest_analyzed_at"] or datetime.now().strftime("%Y-%m-%d %H:%M")
        for r in st["latest_results"]:
            if r.get("Blocked") == "Blocked":
                rows.append({"Date of Analyzing the IP": at, "IP": st["latest_ip"],
                             "Blocked Vendor Name": r.get("Vendor","N/A"),
                             "Status": "Blocked", "Reason": r.get("Reason","Nil"),
                             "Last Reported Date": r.get("Last_Reported","Nil"),
                             "Total Reports": r.get("Total_Reports","N/A")})
        prefix = f"{st['latest_ip']}_Blocked_Report"
    else:
        flash("Scan an IP first before downloading a report.", "danger")
        return redirect(url_for("dashboard"))

    if not rows:
        flash("No blocked vendors found for this scan.", "info")
        return redirect(request.referrer or url_for("dashboard"))

    buf = StringIO()
    pd.DataFrame(rows, columns=cols).to_csv(buf, index=False)
    fname = f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})

# ── Admin area ───────────────────────────────────────────────────────────────
# Everything below is reachable only by accounts on the nakoatech.com domain.
# Admins manage user accounts, reset forgotten passwords, and configure
# each user's own email/SMTP delivery settings individually.

@app.route("/admin")
@admin_required
def admin_dashboard():
    users = list_users_summary()
    return render_template(
        "admin_dashboard.html",
        users=users,
        total_users=len([u for u in users if u["role"] == "user"]),
        total_admins=len([u for u in users if u["role"] == "admin"]),
        total_mail_configured=len([u for u in users if u["mail_configured"]]),
        active_page="admin_dashboard",
    )

@app.route("/admin/users")
@admin_required
def admin_users():
    users = list_users_summary()
    return render_template("admin_users.html", users=users, active_page="admin_users")

@app.route("/admin/users/create", methods=["POST"])
@admin_required
def admin_users_create():
    email    = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm  = request.form.get("confirm_password", "")
    if password != confirm:
        flash("Password and confirmation do not match.", "danger")
    else:
        ok, msg = admin_create_user(email, password)
        flash(msg, "success" if ok else "danger")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/reset-password", methods=["POST"])
@admin_required
def admin_users_reset_password():
    target_email = request.form.get("target_email", "").strip().lower()
    new_password = request.form.get("new_password", "")
    confirm       = request.form.get("confirm_password", "")
    if new_password != confirm:
        flash("New password and confirmation do not match.", "danger")
    else:
        ok, msg = admin_reset_password(target_email, new_password)
        flash(msg, "success" if ok else "danger")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/delete", methods=["POST"])
@admin_required
def admin_users_delete():
    target_email = request.form.get("target_email", "").strip().lower()
    ok, msg = admin_delete_user(target_email, session["user_email"])
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("admin_users"))

@app.route("/admin/email-config")
@admin_required
def admin_email_config():
    """List every user account. Clicking a user opens that user's own
    email configuration editor."""
    users = list_users_summary()
    return render_template(
        "admin_email_config.html",
        users=users,
        active_page="admin_email_config",
    )

@app.route("/admin/email-config/<target_email>", methods=["GET", "POST"])
@admin_required
def admin_email_config_edit(target_email):
    """Edit one specific user's mail/SMTP configuration. Each user has
    their own sender/recipient/SMTP server, so their scheduled report is
    emailed using their own settings only."""
    target_email = target_email.strip().lower()
    target_user = get_user(target_email)
    if target_user is None:
        flash("User not found.", "danger")
        return redirect(url_for("admin_email_config"))

    if request.method == "POST":
        new_settings = {
            "mail_sender":        request.form.get("mail_sender", "").strip(),
            "mail_smtp_password": request.form.get("mail_smtp_password", "").strip(),
            "mail_recipient":     request.form.get("mail_recipient", "").strip(),
            "smtp_server":        request.form.get("smtp_server", "").strip(),
            "smtp_port":          request.form.get("smtp_port", 587),
            "smtp_security":      request.form.get("smtp_security", "TLS").strip(),
        }
        ok, msg = admin_save_user_mail_settings(target_email, new_settings)
        flash(msg, "success" if ok else "danger")
        return redirect(url_for("admin_email_config_edit", target_email=target_email))

    mail_settings = get_user_mail_settings(target_email)
    return render_template(
        "admin_email_config_edit.html",
        target_email=target_email,
        target_role=get_role_for_email(target_email),
        s=mail_settings,
        mail_configured=mail_is_configured(mail_settings),
        active_page="admin_email_config",
    )

@app.route("/admin/profile", methods=["GET", "POST"])
@admin_required
def admin_profile():
    """Admins change their own password here (the equivalent of the
    regular user's Security tab)."""
    email = session["user_email"]
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new     = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if new != confirm:
            flash("New passwords do not match.", "danger")
        else:
            ok, msg = change_password(email, current, new)
            flash(msg, "success" if ok else "danger")
        return redirect(url_for("admin_profile"))
    return render_template("admin_profile.html", active_page="admin_profile")

# ── Startup ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        start_scheduler(process_single_ip)
    app.run(debug=True)
