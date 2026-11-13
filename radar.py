import json
import os
import requests
import feedparser

STATE_FILE = "seen_alerts.json"
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")
TEST_MODE = os.environ.get("TEST_MODE", "false").lower() == "true"

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

def build_url(scheme, host, path):
    return f"{scheme}://{host}{path}"

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
            print(f"Slack delivered ({resp.status_code}): {title[:55]}")
        except Exception as e:
            print(f"Slack post failed: {e}")

def check_cisa_kev(seen):
    try:
        url = build_url("https", "raw.githubusercontent.com", "/cisagov/kev-data/main/known_exploited_vulnerabilities.json")
        resp = requests.get(url, timeout=20)
        if resp.status_code != 200:
            print(f"CISA KEV HTTP {resp.status_code}")
            return
        vulns = resp.json().get("vulnerabilities", [])
        vulns_sorted = sorted(vulns, key=lambda x: x.get("dateAdded", ""), reverse=True)[:40]
        sent = 0
        for v in vulns_sorted:
            cve_id = v.get("cveID", "")
            uid = f"KEV-{cve_id}"
            blob = f"{v.get('vendorProject', '')} {v.get('product', '')} {v.get('vulnerabilityName', '')}"
            if not matches_stack(blob):
                continue
            if uid not in seen or (TEST_MODE and sent < 2):
                cve_link = build_url("https", "www.cve.org", f"/CVERecord?id={cve_id}")
                send_alert(
                    "CISA KEV - ACTIVE EXPLOIT",
                    f"{cve_id} ({v.get('vendorProject')} {v.get('product')})",
                    f"{v.get('vulnerabilityName')} | Due: {v.get('dueDate')} | {v.get('requiredAction')}",
                    cve_link
                )
                sent += 1
            seen.add(uid)
        print(f"CISA KEV check completed (scanned {len(vulns)} total). Sent {sent} alerts.")
    except Exception as e:
        print(f"CISA KEV error: {e}")

def check_osv_ai_cloud(seen):
    try:
        api_url = build_url("https", "api.osv.dev", "/v1/query")
        packages = [
            ("PyPI", "mcp"),
            ("PyPI", "langchain"),
            ("PyPI", "langchain-core"),
            ("npm", "@modelcontextprotocol/sdk"),
            ("Go", "k8s.io/kubernetes")
        ]
        sent = 0
        for eco, pkg in packages:
            resp = requests.post(api_url, json={"package": {"ecosystem": eco, "name": pkg}}, timeout=15)
            if resp.status_code != 200:
                continue
            vulns = resp.json().get("vulns", [])[-5:]
            for v in vulns:
                vid = v.get("id", "")
                uid = f"OSV-{vid}"
                if not vid:
                    continue
                if uid not in seen or (TEST_MODE and sent < 1):
                    summary = v.get("summary") or v.get("details", "Vulnerability detected")[:220]
                    osv_link = build_url("https", "osv.dev", f"/vulnerability/{vid}")
                    send_alert(
                        f"AI / MCP / Cloud Supply Chain ({pkg})",
                        vid,
                        summary[:240],
                        osv_link
                    )
                    sent += 1
                seen.add(uid)
        print(f"OSV AI/MCP/Cloud check completed. Sent {sent} alerts.")
    except Exception as e:
        print(f"OSV error: {e}")

def check_rss_feeds(seen):
    feeds = [
        ("Palo Alto Networks PSIRT", "://paloaltonetworks.com", "/rss.xml", True),
        ("FortiGuard PSIRT", "://fortinet.com", "/rss/ir.xml", True),
        ("Cisco Security Advisories", "://cisco.com", "/security/center/psirtrss20/CiscoSecurityAdvisory.xml", True),
        ("CISA Advisories", "www.cisa.gov", "/cybersecurity-advisories/all.xml", True),
        ("Unit 42 (Palo Alto Intel)", "://paloaltonetworks.com", "/feed/", True),
        ("The Hacker News (Check Point/Zscaler/Zero-Days)", "://feedburner.com", "/TheHackersNews", False),
        ("BleepingComputer (SASE/Firewalls/Breaches)", "://bleepingcomputer.com", "/feed/", False),
        ("SecurityWeek (Enterprise/Financial/ICS)", "://feedburner.com", "/securityweek", False)
    ]
    for source_name, host, path, is_direct_vendor in feeds:
        try:
            feed_url = build_url("https", host, path)
            parsed = feedparser.parse(feed_url, agent="Mozilla/5.0")
            entries = parsed.entries[:15]
            sent = 0
            for entry in entries:
                uid = f"RSS-{entry.get('id', entry.get('link'))}"
                text_blob = f"{entry.get('title', '')} {entry.get('summary', '')}"
                if not is_direct_vendor and not matches_stack(text_blob):
                    continue
                if uid not in seen or (TEST_MODE and sent < 1 and is_direct_vendor):
                    send_alert(
                        source_name,
                        entry.get("title", "New Advisory"),
                        entry.get("summary", "")[:240] + "...",
                        entry.get("link", "")
                    )
                    sent += 1
                seen.add(uid)
            print(f"{source_name} check completed (parsed {len(entries)} items). Sent {sent} alerts.")
        except Exception as e:
            print(f"{source_name} skipped: {e}")

def main():
    print(f"Starting Radar Scan (TEST_MODE={TEST_MODE})...")
    seen = load_seen()
    check_cisa_kev(seen)
    check_osv_ai_cloud(seen)
    check_rss_feeds(seen)
    save_seen(seen)
    print("Radar scan finished cleanly.")

if __name__ == "__main__":
    main()
