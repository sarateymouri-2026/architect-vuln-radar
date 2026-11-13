import json
import os
import gzip
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

def check_github_advisories(seen):
    try:
        url = "https://github.com"
        params = {"type": "reviewed", "severity": "critical,high", "per_page": 40}
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "VulnRadar-Script"
        }
        resp = requests.get(url, params=params, headers=headers, timeout=20)
        if resp.status_code != 200:
            print(f"GitHub Advisories returned HTTP {resp.status_code}: {resp.text[:100]}")
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
        print(f"GitHub Advisories error: {e}")

def check_nvd_feed(seen):
    try:
        # Official NIST NVD Modified JSON GZIP feed (fast, reliable, no API key needed)
        url = "https://nist.gov"
        resp = requests.get(url, headers={"User-Agent": "VulnRadar-Script"}, timeout=30)
        if resp.status_code != 200:
            print(f"NVD Feed HTTP {resp.status_code}")
            return
        raw_json = gzip.decompress(resp.content).decode("utf-8")
        data = json.loads(raw_json)
        items = data.get("CVE_Items", [])
        sent = 0
        # Check the 100 most recently modified/published CVEs
        for item in items[-100:]:
            cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
            uid = f"NVD-{cve_id}"
            if uid in seen or not cve_id:
                continue
            desc_list = item.get("cve", {}).get("description", {}).get("description_data", [])
            desc_text = desc_list[0].get("value", "") if desc_list else ""
            if matches_stack(desc_text):
                send_alert(
                    "NVD Critical/Recent CVE",
                    cve_id,
                    desc_text[:280] + "...",
                    f"https://nist.gov{cve_id}"
                )
                sent += 1
            seen.add(uid)
        print(f"NVD Feed check completed. Sent {sent} alerts.")
    except Exception as e:
        print(f"NVD Feed error: {e}")

def check_cisa_and_security_feeds(seen):
    feeds = {
        "CISA Advisories & KEV": "https://cisa.gov",
        "FortiGuard PSIRT": "https://fortinet.com",
        "BleepingComputer": "https://bleepingcomputer.com",
        "The Hacker News": "https://feedburner.com",
        "Dark Reading": "https://darkreading.com"
    }
    for source_name, feed_url in feeds.items():
        try:
            resp = requests.get(feed_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=20)
            parsed = feedparser.parse(resp.content)
            sent = 0
            for entry in parsed.entries[:20]:
                uid = f"RSS-{entry.get('id', entry.get('link'))}"
                if uid in seen:
                    continue
                text_blob = f"{entry.get('title', '')} {entry.get('summary', '')}"
                if source_name in ["CISA Advisories & KEV", "FortiGuard PSIRT"] or matches_stack(text_blob):
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
    check_github_advisories(seen)
    check_nvd_feed(seen)
    check_cisa_and_security_feeds(seen)
    save_seen(seen)
    print("Radar scan finished cleanly.")

if __name__ == "__main__":
    main()
