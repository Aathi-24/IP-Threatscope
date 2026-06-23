import requests
import pandas as pd
import json
from datetime import datetime

def abuseipdb(ip):
    API_KEY = "0ef8bc21a09b3512c27bad77fb63602851a760ed70efb89b49be2eba0c0e3fb30ac3ca8098cdc17f"
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": ""
    }

    response = requests.get(
        url,
        headers=headers,
        params=params
    )

    if response.status_code == 200:
        data = response.json()
        score = data["data"]["abuseConfidenceScore"]
        reports = data["data"]["totalReports"]

        if score >= 50 and reports >= 10:
            status = "Blocked"
        else:
            status = "Safe"
        
        if(status == "Blocked"):
            if score == 0:
                reason = "Clean"
            elif score < 50:
                reason = "Suspicious"
            else:
                reason = "Malicious"
        else:
            reason = "Nil"
        
        last_reported = data["data"].get("lastReportedAt")
        if last_reported:
            date = last_reported.split("T")[0]
        else:
            date = "Nil"

        # Combined dict: keeps the original detailed fields (used on the
        # /details page) AND the standardized "Vendor / Blocked / Reason"
        # fields (used in the main results table), so AbuseIPDB shows up
        # alongside VirusTotal's engines instead of being dropped.
        return {
            "Vendor" : "AbuseIPDB",
            "Blocked" : status,
            "Reason" : reason,
            "Total_Reports": reports,
            "Last_Reported" : date,
            "Link": f"https://www.abuseipdb.com/check/{ip}",

            "Abuse_Score": score,
            "ISP": data["data"]["isp"],
            "Country" : data["data"]["countryName"],
            "Usage_Type" : data["data"]["usageType"],
            "Domain" : data["data"]["domain"],
            "IP_Version" : data["data"]["ipVersion"],
            "Is_Public" : data["data"]["isPublic"],
            "Host_Names" : data["data"]["hostnames"],
            "Is_Whitelisted" : data["data"]["isWhitelisted"]
        }
    
    else:
        return None
    
def virustotal(ip):
    API_KEY = "1840ec0af3668a612149e6b3aae3895f7048b52de22d3ba2018059f1f01b3b95"

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        attributes = data["data"]["attributes"]

        timestamp = attributes.get("last_modification_date")
        if timestamp:
            last_reported = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d")
        else:
            last_reported = "Nil"

        stats = attributes["last_analysis_stats"]
        total_reports = (stats.get("malicious", 0) + stats.get("suspicious", 0))

        vendor_results = attributes.get("last_analysis_results",{})
        final_results = []

        for vendor, result in vendor_results.items():
            category = result.get("category", "").lower()
            if category in ["malicious", "suspicious"]:
                blocked = "Blocked"
                reason = result.get("result",category.title())

            else:
                blocked = "Safe"
                reason = "Nil"

            final_results.append(
                {
                    "Vendor": vendor,
                    "Blocked": blocked,
                    "Reason": reason,
                    "Total_Reports": total_reports,
                    "Last_Reported": last_reported,
                    "Link": f"https://www.virustotal.com/gui/ip-address/{ip}/detection",
                }
            )
        return final_results
    
    else:
        return None
    
if __name__ == "__main__":
    ip = input("Enter an IP : ")
    result = []
    abip = abuseipdb(ip)
    result.append(abip)

    vtres = virustotal(ip)
    for vt in vtres:
        result.append(vt)

    df = pd.DataFrame(result, index = (range(1,len(result)+1)))
    df.to_csv("Reports_of_IP.csv", mode = "w", index = False)