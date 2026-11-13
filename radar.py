import json
import os
import requests
import feedparser

STATE_FILE = "seen_alerts.json"
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "application/json, text/xml, application/xml, */*"
}

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
    else:
        print("WARNING: WEBHOOK_URL secret is empty!")
        print(message)

def check_cisa_kev(seen):
    try:
        # Official CISA GitHub mirror / feed fallback + direct CISA JSON
        urls = [
            "https://cisa.gov",
            "https://githubusercontent.com"
        ]
        data = None
        for url in urls:
            resp = requests.get(url, headers=BROWSER_HEADERS, timeout=20)
            if resp.status_code == 200 and resp.text.strip().startswith("{"):
                data = resp.json()
                break
        if not data:
            print("CISA KEV: No valid JSON returned.")
            return

        sent = 0
        # Check the 50 most recently added KEV entries
        vulns = sorted(data.get("vulnerabilities", []), key=lambda x: x.get("dateAdded", ""), reverse=True)[:50]
        for v in vulns:
            uid = f"KEV-{v['cveID']}"
            if uid in seen:
                continue
            blob = f"{v.get('vendorProject')} {v.get('product')} {v.get('vulnerabilityName')}"
            if matches_stack(blob):
                send_alert(
                    "CISA KEV - ACTIVE EXPLOIT",
                    f"{v['cveID']} ({v['vendorProject']} {v['product']})",
                    f"{v['vulnerabilityName']} | Action: {v['requiredAction']}",
                    f"https://nist.gov{v['cveID']}"
                )
                sent += 1
            seen.add(uid)
        print(f"CISA KEV check completed. Sent {sent} alerts.")
    except Exception as e:
        print(f"CISA KEV check skipped due to error: {e}")

def check_github_advisories(seen):
    try:
        url = "https://github.com"
        gh_headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        resp = requests.get(url, headers=gh_headers, timeout=20)
        if resp.status_code != 200:
            print(f"GitHub Advisories returned HTTP {resp.status_code}")
            return
        data = resp.json()
        sent = 0
        for adv in data:
            ghsa = adv.get("ghsa_id", "")
            uid = f"GHSA-{ghsa}"
            if uid in seen or not ghsa:
                continue
            blob = f"{adv.get('summary', '')} {adv.get('description', '')}"
            if matches_stack(blob):
                cve = adv.get("cve_id") or ghsa
                send_alert(
                    "GitHub Advisory (AI/Cloud/CI-CD)",
                    f"{cve} ({adv.get('severity', '').upper()})",
                    adv.get("summary", ""),
                    adv.get("html_url", "")
                )
                sent += 1
            seen.add(uid)
        print(f"GitHub Advisories check completed. Sent {sent} alerts.")
    except Exception as e:
        print(f"GitHub Advisories check skipped due to error: {e}")

def check_nvd_recent(seen):
    try:
        # Pulls latest Critical/High CVEs across Check Point, Zscaler, Palo Alto, Fortinet, AI/MCP
        url = "https://nist.gov"
        resp = requests.get(url, headers=BROWSER_HEADERS, timeout=25)
        if resp.status_code != 200:
            print(f"NVD API returned HTTP {resp.status_code}")
            return
        items = resp.json().get("vulnerabilities", [])
        sent = 0
        for item in items:
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id", "")
            uid = f"NVD-{cve_id}"
            if uid in seen or not cve_id:
                continue
            descriptions = cve_obj.get("descriptions", [])
            desc_text = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            if matches_stack(desc_text):
                send_alert(
                    "NVD CVE Alert",
                    cve_id,
                    desc_text[:280] + "...",
                    f"https://nist.gov{cve_id}"
                )
                sent += 1
            seen.add(uid)
        print(f"NVD check completed. Sent {sent} alerts.")
    except Exception as e:
        print(f"NVD check skipped due to error: {e}")

def check_rss_feeds(seen):
    feeds = {
        "FortiGuard PSIRT": "https://fortinet.com",
        "BleepingComputer Security": "https://bleepingcomputer.com",
        "The Hacker News": "https://feedburner.com"
    }
    for source_name, feed_url in feeds.items():
        try:
            resp = requests.get(feed_url, headers=BROWSER_HEADERS, timeout=20)
            parsed = feedparser.parse(resp.content)
            sent = 0
            for entry in parsed.entries[:15]:
                uid = f"RSS-{entry.get('id', entry.get('link'))}"
                if uid in seen:
                    continue
                text_blob = f"{entry.get('title', '')} {entry.get('summary', '')}"
                if source_name == "FortiGuard PSIRT" or matches_stack(text_blob):
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
            print(f"{source_name} check skipped due to error: {e}")

def main():
    first_run = not os.path.exists(STATE_FILE)
    seen = load_seen()
    if first_run:
        send_alert(
            "System Online",
            "Architect Vulnerability Radar Activated",
            "Monitoring CISA KEV, NVD, GitHub Advisories (AI/MCP/CI-CD), FortiGuard, and zero-day feeds for your stack.",
            "https://github.com"
        )
    check_cisa_kev(seen)
    check_github_advisories(seen)
    check_nvd_recent(seen)
    check_rss_feeds(seen)
    save_seen(seen)
    print("Radar scan finished cleanly.")

if __name__ == "__main__":
    main()
