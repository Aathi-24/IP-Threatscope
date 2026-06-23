from functools import wraps
from io import StringIO
from flask import (Flask, render_template, request, send_file, Response,
                   flash, redirect, url_for, session, jsonify)
from services.main_file import abuseipdb, virustotal
from services.extra_vendors import greynoise, ipqualityscore, shodan_internetdb
from services.scheduler import start_scheduler, get_scheduler_status_for_user, _run_check_for_user
from services.auth import (
    register_user, verify_login, change_password,
    save_user_settings, get_user_ips, add_user_ip, add_user_ips_bulk,
    remove_user_ip, get_user, get_user_scheduler_state, save_user_scheduler_state,
)
from ipwhois import IPWhois
import pandas as pd
import ipaddress
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = "ipt_secret_key_change_in_production_32chars"

APP_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Per-user in-memory scan state
# Replaces the old bare globals (latest_results, batch_ips, …).
# Keyed by user email; entries are created lazily on first access.
# ---------------------------------------------------------------------------
_user_state: dict = {}


def _get_state(email: str) -> dict:
    if email not in _user_state:
        _user_state[email] = {
            "latest_results": [],
            "latest_ip": None,
            "latest_analyzed_at": None,
            "batch_ips": [],
            "batch_results": {},
            "current_batch_index": 0,
            "scan_history": [],          # list of {ip, verdict, blocked, total, analyzed_at}
        }
    return _user_state[email]


def _add_to_history(email: str, ip: str, data: dict):
    """Prepend a compact summary of a scan to the user's in-memory history."""
    st = _get_state(email)
    entry = {
        "ip":          ip,
        "verdict":     data.get("verdict", "Safe"),
        "blocked":     data.get("blocked", 0),
        "total":       data.get("total", 0),
        "analyzed_at": data.get("analyzed_at", datetime.now().strftime("%Y-%m-%d %H:%M")),
    }
    # Avoid duplicating consecutive scans of the same IP
    history = st["scan_history"]
    if history and history[0]["ip"] == ip:
        history[0] = entry
    else:
        history.insert(0, entry)
    st["scan_history"] = history[:10]   # keep last 10


# ---------------------------------------------------------------------------
# Login required decorator
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_email" not in session:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# No-cache headers so navigating between batch IPs never shows stale pages
# ---------------------------------------------------------------------------
@app.after_request
def add_no_cache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ---------------------------------------------------------------------------
# IP processing helpers
# ---------------------------------------------------------------------------
def extract_ips_from_text(text: str) -> list:
    ips = []
    for line in text.strip().splitlines():
        ip = line.strip().strip(",").strip(";")
        if not ip:
            continue
        try:
            ipaddress.ip_address(ip)
            ips.append(ip)
        except ValueError:
            continue
    return ips


def process_single_ip(ip: str) -> dict:
    analyzed_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    try:
        abuse_data = abuseipdb(ip)
        vt_results = virustotal(ip) or []

        extra_rows = []
        if abuse_data:
            extra_rows.append({
                "Vendor":        abuse_data.get("Vendor", "AbuseIPDB"),
                "Blocked":       abuse_data.get("Blocked", "Safe"),
                "Reason":        abuse_data.get("Reason", "Nil"),
                "Total_Reports": abuse_data.get("Total_Reports", "N/A"),
                "Last_Reported": abuse_data.get("Last_Reported", "Nil"),
                "Link":          abuse_data.get("Link", f"https://www.abuseipdb.com/check/{ip}"),
            })

        for fn in (greynoise, ipqualityscore, shodan_internetdb):
            row = fn(ip)
            if row:
                extra_rows.append(row)

        results = extra_rows + vt_results
        total   = len(results)
        blocked = sum(1 for r in results if r["Blocked"] == "Blocked")
        safe    = total - blocked

        if vt_results:
            total_reports = vt_results[0].get("Total_Reports")
            last_reported = vt_results[0].get("Last_Reported")
        elif abuse_data:
            total_reports = abuse_data.get("Total_Reports")
            last_reported = abuse_data.get("Last_Reported")
        else:
            total_reports = last_reported = "N/A"

        return {
            "results": results, "total": total, "safe": safe,
            "blocked": blocked,
            "verdict": "Suspicious" if blocked > 0 else "Safe",
            "total_reports": total_reports, "last_reported": last_reported,
            "analyzed_at": analyzed_at, "error": None,
        }
    except Exception as e:
        return {
            "results": [], "total": 0, "safe": 0, "blocked": 0,
            "verdict": "Error", "total_reports": "N/A", "last_reported": "N/A",
            "analyzed_at": analyzed_at, "error": str(e),
        }


# ---------------------------------------------------------------------------
# Context processor – injects common variables into every template that
# extends base.html (user object, scan history, scheduler status) so that
# each route only needs to pass page-specific variables like active_page.
# ---------------------------------------------------------------------------
@app.context_processor
def inject_common():
    """Available in every template as {{ user }}, {{ scan_history }},
    {{ scheduler_status }}, and {{ active_page }} (defaults to '')."""
    email = session.get("user_email")
    if not email:
        return {}
    st = _get_state(email)
    try:
        user = get_user(email)
        sched = get_scheduler_status_for_user(email)
    except Exception:
        user = {"settings": {}, "ips": []}
        sched = {"last_success_at": "Never", "next_check_eta": "N/A", "interval_minutes": 0}
    return {
        "user": user,
        "scan_history": st["scan_history"],
        "scheduler_status": sched,
        "active_page": "",   # each route overrides this via render_template kwarg
    }


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_email" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        ok, msg  = verify_login(email, password)
        if ok:
            session["user_email"] = email
            return redirect(url_for("dashboard"))
        flash(msg, "danger")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_email" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html", email=email)

        ok, msg = register_user(email, password)
        if ok:
            flash(msg, "success")
            return redirect(url_for("login"))
        flash(msg, "danger")
        return render_template("register.html", email=email)

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_pwd():
    email = session["user_email"]

    if request.method == "POST":
        current = request.form.get("current_password", "")
        new     = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        if new != confirm:
            flash("New passwords do not match.", "danger")
            return render_template("change_password.html", active_page="change_pwd")

        ok, msg = change_password(email, current, new)
        flash(msg, "success" if ok else "danger")
        if ok:
            return redirect(url_for("dashboard"))

    return render_template("change_password.html", active_page="change_pwd")


# ---------------------------------------------------------------------------
# Settings (mail config + scheduler + IP list management)
# ---------------------------------------------------------------------------
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    email = session["user_email"]
    user  = get_user(email)

    if request.method == "POST":
        action = request.form.get("action", "")

        if action == "save_settings":
            new_settings = {
                "mail_sender":              request.form.get("mail_sender", "").strip(),
                "mail_recipient":           request.form.get("mail_recipient", "").strip(),
                "mail_app_password":        request.form.get("mail_app_password", "").strip(),
                "smtp_server":              request.form.get("smtp_server", "smtp.gmail.com").strip(),
                "smtp_port":                request.form.get("smtp_port", 587),
                "check_interval_minutes":   request.form.get("check_interval_minutes", 60),
                "missed_check_grace_minutes": request.form.get("missed_check_grace_minutes", 10),
            }
            ok, msg = save_user_settings(email, new_settings)
            flash(msg, "success" if ok else "danger")

        elif action == "add_ip":
            ip      = request.form.get("new_ip", "").strip()
            ok, msg = add_user_ip(email, ip)
            flash(msg, "success" if ok else "danger")

        elif action == "bulk_add_ips":
            raw            = request.form.get("bulk_ips", "")
            added, skipped = add_user_ips_bulk(email, raw)
            if added:
                flash(f"Added {len(added)} IP(s): {', '.join(added)}", "success")
            if skipped:
                flash(f"Skipped {len(skipped)} (already exist or invalid): {', '.join(skipped)}", "warning")

        elif action == "remove_ip":
            ip      = request.form.get("ip_to_remove", "").strip()
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
                    state["last_success_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
                    state["last_success_iso"] = now_iso
                    state["last_email_sent_at"] = now_iso
                    state["last_alert_sent_for"] = None
                    save_user_scheduler_state(email, state)
                    flash("Check started! Report will be sent shortly. Next scheduled check will be in " + 
                          str(user["settings"].get("check_interval_minutes", 60)) + " minutes.", "success")
                except Exception as e:
                    flash(f"Error running check: {e}", "danger")

        return redirect(url_for("settings"))

    user    = get_user(email)   # re-fetch after any save
    sched   = get_scheduler_status_for_user(email)
    return render_template("settings.html",
                           user=user, scheduler_status=sched,
                           active_page="settings")


# ---------------------------------------------------------------------------
# Dashboard (main page after login)
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
@login_required
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
        st["latest_results"]    = data["results"]
        st["latest_ip"]         = ip
        st["latest_analyzed_at"] = data["analyzed_at"]
        # Clear batch state so vendor-details page knows we're in single-IP mode
        st["batch_ips"]         = []
        st["batch_results"]     = {}
        st["current_batch_index"] = 0
        # Record in scan history
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


# ---------------------------------------------------------------------------
# Batch run (reads IPs from the user's own JSON record)
# ---------------------------------------------------------------------------
@app.route("/run-batch")
@login_required
def run_batch():
    email = session["user_email"]
    st    = _get_state(email)

    ips = get_user_ips(email)
    if not ips:
        flash("Your IP list is empty. Add IPs in Account Settings first.", "warning")
        return redirect(url_for("settings"))

    st["batch_ips"]           = ips
    st["batch_results"]       = {}
    st["current_batch_index"] = 0
    flash(f"Loaded {len(ips)} IP(s) from your list.", "success")
    return redirect(url_for("view_batch_ip", index=0))


@app.route("/batch/<int:index>")
@login_required
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
    # Record in scan history
    _add_to_history(email, ip, data)

    batch_info = {
        "current":  index + 1,
        "total":    len(st["batch_ips"]),
        "has_next": index < len(st["batch_ips"]) - 1,
        "has_prev": index > 0,
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


# ---------------------------------------------------------------------------
# Vendor details
# ---------------------------------------------------------------------------
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
                        "ip":           ip,
                        "status":       row.get("Blocked", "N/A"),
                        "reason":       row.get("Reason", "Nil"),
                        "last_reported": row.get("Last_Reported", "Nil"),
                        "total_reports": row.get("Total_Reports", "N/A"),
                    })
                    break
    elif st["latest_ip"] and st["latest_results"]:
        for row in st["latest_results"]:
            if row.get("Vendor") == vendor_name:
                rows.append({
                    "ip":           st["latest_ip"],
                    "status":       row.get("Blocked", "N/A"),
                    "reason":       row.get("Reason", "Nil"),
                    "last_reported": row.get("Last_Reported", "Nil"),
                    "total_reports": row.get("Total_Reports", "N/A"),
                })
                break

    return rows


@app.route("/vendor/<vendor_name>")
@login_required
def vendor_details(vendor_name):
    email = session["user_email"]
    rows  = _get_vendor_rows(email, vendor_name)

    if not rows:
        flash(f"No results found for vendor '{vendor_name}'.", "danger")
        return redirect(url_for("dashboard"))

    st = _get_state(email)
    return render_template("vendor_details.html",
                           vendor_name=vendor_name, rows=rows,
                           is_batch=bool(st["batch_ips"]),
                           active_page="")


# ---------------------------------------------------------------------------
# WHOIS details page
# ---------------------------------------------------------------------------
def _whois_lookup(ip):
    try:
        obj    = IPWhois(ip)
        result = obj.lookup_rdap()
        net    = result.get("network", {})
        return {
            "asn":            result.get("asn", "N/A"),
            "asn_registry":   result.get("asn_registry", "N/A"),
            "asn_cidr":       result.get("asn_cidr", "N/A"),
            "asn_country_code": result.get("asn_country_code", "N/A"),
            "asn_date":       result.get("asn_date", "N/A"),
            "asn_description": result.get("asn_description", "N/A"),
            "network_name":   net.get("name", "N/A"),
            "network_handle": net.get("handle", "N/A"),
            "network_type":   net.get("type", "N/A"),
            "country":        net.get("country", "N/A"),
            "cidr":           net.get("cidr", "N/A"),
            "start_address":  net.get("start_address", "N/A"),
            "end_address":    net.get("end_address", "N/A"),
            "created":        (net.get("events", [{}])[0].get("timestamp", "N/A")
                               if net.get("events") else "N/A"),
            "remarks":        net.get("remarks", "N/A"),
        }
    except Exception:
        return {k: "N/A" for k in [
            "asn","asn_registry","asn_cidr","asn_country_code","asn_date",
            "asn_description","network_name","network_handle","network_type",
            "country","cidr","start_address","end_address","created","remarks",
        ]}


@app.route("/details/<ip>")
@login_required
def details(ip):
    return render_template("details.html", ip=ip,
                           whois=_whois_lookup(ip),
                           abuse=abuseipdb(ip),
                           active_page="")


# ---------------------------------------------------------------------------
# CSV downloads
# ---------------------------------------------------------------------------
@app.route("/download/<ip>")
@login_required
def download_csv(ip):
    email = session["user_email"]
    st    = _get_state(email)
    df    = pd.DataFrame(st["latest_results"])
    buf   = StringIO()
    df.to_csv(buf, index=False)
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":
                             f"attachment; filename={ip}_results.csv"})


@app.route("/download_blocked_report")
@login_required
def download_blocked_report():
    email = session["user_email"]
    st    = _get_state(email)

    columns = [
        "Date of Analyzing the IP", "IP", "Blocked Vendor Name",
        "Status", "Reason", "Last Reported Date", "Total Reports",
    ]
    report_rows = []

    if st["batch_ips"]:
        # Batch mode - ensure ALL IPs in the batch are processed
        for ip in st["batch_ips"]:
            if ip not in st["batch_results"]:
                st["batch_results"][ip] = process_single_ip(ip)

        for ip in st["batch_ips"]:
            data = st["batch_results"].get(ip)
            if not data:
                continue
            at = data.get("analyzed_at", datetime.now().strftime("%Y-%m-%d %H:%M"))
            for row in data["results"]:
                if row.get("Blocked") == "Blocked":
                    report_rows.append({
                        "Date of Analyzing the IP": at,
                        "IP": ip,
                        "Blocked Vendor Name": row.get("Vendor", "N/A"),
                        "Status": "Blocked",
                        "Reason": row.get("Reason", "Nil"),
                        "Last Reported Date": row.get("Last_Reported", "Nil"),
                        "Total Reports": row.get("Total_Reports", "N/A"),
                    })
        filename_prefix = "Blocked_Report"

    elif st["latest_ip"] and st["latest_results"]:
        # Single IP mode - instant, reuses cached results
        at = st["latest_analyzed_at"] or datetime.now().strftime("%Y-%m-%d %H:%M")
        for row in st["latest_results"]:
            if row.get("Blocked") == "Blocked":
                report_rows.append({
                    "Date of Analyzing the IP": at,
                    "IP": st["latest_ip"],
                    "Blocked Vendor Name": row.get("Vendor", "N/A"),
                    "Status": "Blocked",
                    "Reason": row.get("Reason", "Nil"),
                    "Last Reported Date": row.get("Last_Reported", "Nil"),
                    "Total Reports": row.get("Total_Reports", "N/A"),
                })
        filename_prefix = f"{st['latest_ip']}_Blocked_Report"

    else:
        flash("Scan an IP first before downloading a blocked report.", "danger")
        return redirect(url_for("dashboard"))

    if not report_rows:
        flash("No vendors blocked this IP." if not st["batch_ips"]
              else "No vendors blocked any IP in your list.", "info")
        return redirect(request.referrer or url_for("dashboard"))

    df  = pd.DataFrame(report_rows, columns=columns)
    buf = StringIO()
    df.to_csv(buf, index=False)
    filename = f"{filename_prefix}_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":
                             f"attachment; filename={filename}"})


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        start_scheduler(process_single_ip)
    app.run(debug=True)
