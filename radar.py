import csv
import io
import json
import os
import requests
import feedparser

STATE_FILE = "seen_alerts.json"
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")

KEYWORDS = [
    # Firewalls & SASE
    "palo alto", "pan-os", "prisma", "globalprotect",
    "fortinet", "fortios", "fortigate", "fortiproxy", "fortisase",
    "check point", "checkpoint", "gaia",
    "zscaler", "cisco", "f5", "big-ip", "ivanti", "citrix", "netscaler",
    # AI, MCP & CI/CD
    "mcp", "model context protocol", "langchain", "openai", "anthropic",
    "gitlab", "github", "jenkins", "terraform", "kubernetes", "docker", "argocd",
    # Cloud & Identity
    "aws", "azure", "entra", "google cloud", "gcp", "okta", "cloudflare", "vmware", "esxi",
    # Financial / Enterprise Core
    "oracle", "weblogic", "sap", "swift", "red hat", "openssl", "nginx"
]

def load_seen():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return set(json.load(f))
    return set()

def save_seen(seen):
    with open(STATE_FILE, "w") as f:
        json.dump(sorted(list(seen)), f, indent=2)

def matches_stack(text):
    text_lower = text.lower()
    return any(kw in text_lower for kw in KEYWORDS)

def send_alert(source, title, summary, link):
    message = (
        f"🚨 *[{source}]* <{link}|{title}>\n"
        f">{summary}"
    )
    if WEBHOOK_URL:
        try:
            resp = requests.post(WEBHOOK_URL, json={"text": message}, timeout=15)
            print(f"Slack status: {resp.status_code}")
        except Exception as e:
            print(f"Slack post failed: {e}")

def check_cisa_kev_csv(seen):
    try:
        # Official CISA KEV CSV (bypasses JSON WAF blocks on cloud runners)
        url = "https://cisa.gov"
        resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=20)
        if resp.status_code != 200 or "cveID" not in resp.text[:200]:
            print(f"CISA KEV CSV status: {resp.status_code}")
            return
        reader = csv.DictReader(io.StringIO(resp.text))
        rows = list(reader)
        sent = 0
        # Check the 40 most recent KEV additions
        for row in rows[:40]:
            cve_id = row.get("cveID", "")
            uid = f"KEV-{cve_id}"
            if uid in seen or not cve_id:
                continue
            blob = f"{row.get('vendorProject', '')} {row.get('product', '')} {row.get('vulnerabilityName', '')}"
            if matches_stack(blob):
                send_alert(
                    "CISA KEV - ACTIVE EXPLOIT",
                    f"{cve_id} ({row.get('vendorProject')} {row.get('product')})",
                    f"{row.get('vulnerabilityName')} | Action: {row.get('requiredAction')}",
                    f"https://cve.org{cve_id}"
                )
                sent += 1
            seen.add(uid)
        print(f"CISA KEV CSV check completed. Sent {sent} alerts.")
    except Exception as e:
        print(f"CISA KEV CSV error: {e}")

def check_redhat_cve_api(seen):
    try:
        # Unthrottled Red Hat Security Data API (covers Linux, OpenSSL, Kubernetes, Cloud, Financial middleware)
        url = "https://redhat.com"
        resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=20)
        if resp.status_code != 200:
            print(f"Red Hat API status: {resp.status_code}")
            return
        items = resp.json()
        sent = 0
        for item in items:
            cve_id = item.get("CVE", "")
            uid = f"RH-{cve_id}"
            if uid in seen or not cve_id:
                continue
            severity = str(item.get("severity", "")).lower()
            desc = item.get("bugzilla_description", "")
            if severity in ["critical", "important"] and matches_stack(desc):
                send_alert(
                    f"Enterprise CVE ({severity.upper()})",
                    cve_id,
                    desc[:260] + "...",
                    f"https://cve.org{cve_id}"
                )
                sent += 1
            seen.add(uid)
        print(f"Enterprise CVE check completed. Sent {sent} alerts.")
    except Exception as e:
        print(f"Enterprise CVE error: {e}")

def check_rss_feeds(seen):
    # Direct Vendor PSIRTs + Threat Intel covering Palo Alto, Fortinet, Cisco, Check Point, Zscaler, AI/MCP, Cloud, Financial
    feeds = {
        "Palo Alto Networks PSIRT": "https://paloaltonetworks.com",
        "FortiGuard PSIRT": "https://fortinet.com",
        "Cisco Security Advisories": "https://cisco.com",
        "CISA Advisories": "https://cisa.gov",
        "Unit 42 (Palo Alto Intel)": "https://paloaltonetworks.com",
        "The Hacker News (Zero-Days/AI/SASE)": "https://feedburner.com",
        "BleepingComputer (Check Point/Zscaler/Breaches)": "https://bleepingcomputer.com",
        "SecurityWeek (Enterprise/Financial/ICS)": "https://feedburner.com"
    }
    for source_name, feed_url in feeds.items():
        try:
            resp = requests.get(feed_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=20)
            parsed = feedparser.parse(resp.content)
            sent = 0
            for entry in parsed.entries[:15]:
                uid = f"RSS-{entry.get('id', entry.get('link'))}"
                if uid in seen:
                    continue
                text_blob = f"{entry.get('title', '')} {entry.get('summary', '')}"
                is_direct_vendor = source_name in [
                    "Palo Alto Networks PSIRT",
                    "FortiGuard PSIRT",
                    "Cisco Security Advisories",
                    "CISA Advisories",
                    "Unit 42 (Palo Alto Intel)"
                ]
                if is_direct_vendor or matches_stack(text_blob):
                    send_alert(
                        source_name,
                        entry.get("title", "New Advisory"),
                        entry.get("summary", "")[:240] + "...",
                        entry.get("link", "")
                    )
                    sent += 1
                seen.add(uid)
            print(f"{source_name} check completed. Sent {sent} alerts.")
        except Exception as e:
            print(f"{source_name} skipped: {e}")

def main():
    seen = load_seen()
    check_cisa_kev_csv(seen)
    check_redhat_cve_api(seen)
    check_rss_feeds(seen)
    save_seen(seen)
    print("Radar scan finished cleanly.")

if __name__ == "__main__":
    main()
