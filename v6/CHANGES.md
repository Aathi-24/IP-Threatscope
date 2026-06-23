# Changes in this version

## 1. AbuseIPDB now shows up in the results table
`abuseipdb()` was already being called in `process_single_ip()`, but its
result was discarded — only VirusTotal's engines made it into the table.
`abuseipdb()` now returns one merged dict that contains both the original
detail fields (still used by `/details/<ip>`) and the standardized
`Vendor / Blocked / Reason / Total_Reports / Last_Reported / Link` fields,
and `app.py` now folds that row into the same results list as VirusTotal.

## 2. New free vendors added (services/extra_vendors.py)
Each one is parsed into the exact same row shape VirusTotal/AbuseIPDB use,
so they all render in the same table. None of these are already part of
VirusTotal's bundled engine list (VT already includes things like
AlienVault, StopForumSpam, CINS Army, GreenSnow, etc., so those were
intentionally skipped to avoid duplicates).

| Vendor | Free tier | API key needed? | Where to get a key |
|---|---|---|---|
| GreyNoise (Community API) | Yes | Optional (raises rate limit) | https://www.greynoise.io/viz/account/ |
| IPQualityScore | Yes (1,000 lookups/month) | Required | https://www.ipqualityscore.com/user/settings |
| Shodan InternetDB | Yes, unlimited for non-commercial use | Not required at all | n/a |

**API keys were intentionally left blank** in `services/extra_vendors.py` —
add your own key to the `API_KEY` variable inside each function. Until a key
is added, GreyNoise still works (unauthenticated, lower rate limit), Shodan
InternetDB always works (no key needed), and IPQualityScore is skipped
(returns `None`) since it requires a key as part of its URL.

## 3. Clickable vendor names
In `templates/result.html`, each vendor name in the results table is now a
link (opens in a new tab) to that vendor's own results page for the
analyzed IP:
- VirusTotal engines → `virustotal.com/gui/ip-address/<ip>/detection`
- AbuseIPDB → `abuseipdb.com/check/<ip>`
- GreyNoise → its own `viz.greynoise.io` link
- Shodan → `shodan.io/host/<ip>`
- IPQualityScore → its free lookup tool page

## 4. Small robustness fix
The old code pulled the "Total Reports / Last Reported" summary from
`results[4]`, which assumed at least 5 VirusTotal rows would always be
first in the list. Now that AbuseIPDB and other vendors are merged in
first, that index would point at the wrong row. This is now read directly
from VirusTotal's own result list (falling back to AbuseIPDB's data if
VirusTotal has none), so it's correct regardless of vendor order.

## 5. Vendor click now goes to an internal vendor-details page (not the vendor's website)
The earlier version made each vendor name link out to that vendor's own
website. That's been replaced:
- `templates/result.html` no longer shows Status/Reason inline — it now
  shows just a plain, clickable list of vendor names.
- Clicking a vendor name goes to a new internal page,
  `templates/vendor_details.html`, served by the new `/vendor/<vendor_name>`
  route in `app.py`. It shows that vendor's Status, Reason, Last Reported,
  and Total Reports for every IP analyzed:
  - Single-IP mode → just that one IP.
  - Batch mode → every IP in the batch that's been viewed so far (results
    are still fetched lazily per IP, same as before — the vendor page
    simply collects whatever has already been cached in `batch_results`).
- A `latest_ip` global was added (alongside the existing `latest_results`)
  so the single-IP case knows which IP its cached results belong to.
- Submitting a brand-new single IP now also clears any leftover batch
  state from a previous file upload, so the vendor-details page doesn't
  mix up batch and single-IP context.

## 6. File upload removed - IPs are now read directly from the server
`templates/index.html` no longer has the "Upload Batch File" form. In its
place is an "Analyze IPs from File" button that hits a new `/run-batch`
route in `app.py`, which reads `uploads/IP.txt` (the file already bundled
in this project, one level above `app.py`) directly off disk, resets any
previous batch state, and starts the batch view at IP #1. The single-IP
text entry box is untouched.

## 7. New "Download Blocked Report" button
On `result.html`, right below "View Full IP Details", there's now a
"Download Blocked Report" button → `/download_blocked_report` in `app.py`.
One click:
- Processes every IP in `uploads/IP.txt` (any IP not already analyzed yet
  gets analyzed right then, so this always covers the whole file in a
  single click, no matter which IP you're currently viewing).
- Builds one combined CSV containing only the vendor rows where that
  vendor blocked that IP, with columns: `Date of Analyzing the IP`
  (`YYYY-MM-DD HH:MM`, recorded at the moment that IP was analyzed), `IP`,
  `Blocked Vendor Name`, `Status`, `Reason`, `Last Reported Date`,
  `Total Reports`.

## 8. Fixed: viewing IP #2 sometimes showed IP #1's results
Added `Cache-Control: no-store`, `Pragma: no-cache`, and `Expires: 0`
headers to every response (`app.after_request`). Without these headers,
browsers can serve a previously-cached copy of a page when navigating
between similarly-structured pages like `/batch/0` → `/batch/1`, which is
what caused the previous IP's results to reappear. Each `/batch/<index>`
request already builds its response strictly from that index's own IP, so
forcing a fresh fetch on every navigation eliminates the stale view.

## 9. Fixed: "Download Blocked Report" ignored single-IP scans
Previously, `/download_blocked_report` always pulled from the whole
`uploads/IP.txt` file, even after scanning just one IP manually - showing
the wrong data, and slow, since it had to call every vendor's API for
every IP in the file that hadn't been looked up yet.

Now it checks which mode you're in:
- **Single-IP scan** (typed an IP and hit Analyze): the report covers only
  that one IP, built directly from the results already fetched for it -
  no extra API calls, so it's instant.
- **Batch run** (via "Analyze IPs from File"): unchanged - still covers
  every IP in the file, analyzing any that haven't been viewed yet.

A new `latest_analyzed_at` global tracks the timestamp for whichever IP
was most recently scanned, so the single-IP report doesn't need to
recompute anything to fill in the "Date of Analyzing the IP" column.
