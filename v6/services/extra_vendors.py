"""
Additional free threat-intelligence vendors.

These vendors are NOT part of VirusTotal's bundled engine list (VirusTotal
already aggregates engines such as AlienVault, StopForumSpam, CINS Army,
GreenSnow, etc., so those are intentionally skipped here to avoid duplicates).
Each vendor below offers a free tier / free API and is parsed into the exact
same row shape produced by main_file.py's virustotal()/abuseipdb():

    {
        "Vendor": "<name>",
        "Blocked": "Blocked" | "Safe",
        "Reason": "<short reason>",
        "Total_Reports": <int or "N/A">,
        "Last_Reported": "<date>" | "Nil",
        "Link": "<url to the vendor's own results page for this IP>"
    }

That way every vendor — VirusTotal engines, AbuseIPDB, and these — can be
rendered by the same table in result.html.

API KEYS: left blank intentionally. Add your own key for each vendor below.
  - GreyNoise Community API : https://www.greynoise.io/viz/account/
  - IPQualityScore          : https://www.ipqualityscore.com/user/settings
  - Shodan InternetDB needs NO key at all (it's a free, keyless endpoint).
"""

import requests


def greynoise(ip):
    """GreyNoise Community API - free tier, works with or without a key
    (an API key just raises the daily lookup limit)."""

    API_KEY = ""  # <-- Add your GreyNoise Community API key here

    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {"Accept": "application/json"}
    if API_KEY:
        headers["key"] = API_KEY

    try:
        response = requests.get(url, headers=headers, timeout=10)
    except requests.RequestException as e:
        return None

    if response.status_code == 200:
        data = response.json()

        noise = data.get("noise", False)
        riot = data.get("riot", False)
        classification = (data.get("classification") or "unknown").lower()
        last_seen = data.get("last_seen") or "Nil"

        if classification == "malicious":
            blocked = "Blocked"
            reason = "Malicious"
        elif classification == "suspicious":
            blocked = "Blocked"
            reason = "Suspicious"
        elif riot:
            blocked = "Safe"
            reason = "Known Benign Service (RIOT)"
        elif noise:
            blocked = "Safe"
            reason = "Internet Scanner (Benign Noise)"
        else:
            blocked = "Safe"
            reason = "Nil"

        return {
            "Vendor": "GreyNoise",
            "Blocked": blocked,
            "Reason": reason,
            "Total_Reports": "N/A",
            "Last_Reported": last_seen,
            "Link": data.get("link", f"https://viz.greynoise.io/ip/{ip}"),
        }

    elif response.status_code == 404:
        # GreyNoise has no record for this IP - that simply means "unseen",
        # not an error.
        return {
            "Vendor": "GreyNoise",
            "Blocked": "Safe",
            "Reason": "No Data Available",
            "Total_Reports": "N/A",
            "Last_Reported": "Nil",
            "Link": f"https://viz.greynoise.io/ip/{ip}",
        }

    else:
        return None


def ipqualityscore(ip):
    """IPQualityScore Proxy/Fraud-Score API - free tier (1,000 lookups/month).
    Skipped entirely if no API key has been configured, since IPQS requires
    the key as part of the URL itself."""

    API_KEY = ""  # <-- Add your IPQualityScore Private API key here

    if not API_KEY:
        return None

    url = f"https://www.ipqualityscore.com/api/json/ip/{API_KEY}/{ip}"
    params = {"strictness": 1, "allow_public_access_points": "true"}

    try:
        response = requests.get(url, params=params, timeout=10)
    except requests.RequestException as e:
        return None

    if response.status_code == 200:
        data = response.json()

        if not data.get("success", False):
            return None

        fraud_score = data.get("fraud_score", 0)
        recent_abuse = data.get("recent_abuse", False)
        is_proxy = data.get("proxy", False)
        is_vpn = data.get("vpn", False)
        is_tor = data.get("tor", False)

        if recent_abuse or fraud_score >= 75:
            blocked = "Blocked"
            reason = "Recent Abuse Reported" if recent_abuse else "High Fraud Score"
        elif fraud_score >= 50 or is_proxy or is_vpn or is_tor:
            blocked = "Blocked"
            reason = "Suspicious (Proxy/VPN/Tor or Elevated Fraud Score)"
        else:
            blocked = "Safe"
            reason = "Nil"

        return {
            "Vendor": "IPQualityScore",
            "Blocked": blocked,
            "Reason": reason,
            "Total_Reports": fraud_score,
            "Last_Reported": "Nil",
            "Link": f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip}",
        }

    else:
        return None


def shodan_internetdb(ip):
    """Shodan InternetDB - completely free, no API key required at all."""

    url = f"https://internetdb.shodan.io/{ip}"

    try:
        response = requests.get(url, timeout=10)
    except requests.RequestException as e:
        return None

    if response.status_code == 200:
        data = response.json()

        vulns = data.get("vulns", []) or []
        tags = data.get("tags", []) or []

        risky_tags = {
            "malware", "botnet", "spam", "proxy", "vpn",
            "tor", "scanner", "compromised", "honeypot",
        }
        flagged_tags = [t for t in tags if t.lower() in risky_tags]

        if vulns or flagged_tags:
            blocked = "Blocked"
            reason_parts = []
            if vulns:
                reason_parts.append(f"{len(vulns)} Known Vulnerabilities")
            if flagged_tags:
                reason_parts.append("Tags: " + ", ".join(flagged_tags))
            reason = "; ".join(reason_parts)
        else:
            blocked = "Safe"
            reason = "Nil"

        return {
            "Vendor": "Shodan",
            "Blocked": blocked,
            "Reason": reason,
            "Total_Reports": len(vulns),
            "Last_Reported": "Nil",
            "Link": f"https://www.shodan.io/host/{ip}",
        }

    elif response.status_code == 404:
        # No Shodan scan data on file for this IP - not an error.
        return {
            "Vendor": "Shodan",
            "Blocked": "Safe",
            "Reason": "No Data Available",
            "Total_Reports": 0,
            "Last_Reported": "Nil",
            "Link": f"https://www.shodan.io/host/{ip}",
        }

    else:
        return None
