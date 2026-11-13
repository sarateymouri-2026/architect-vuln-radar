import json
import os
import requests
import feedparser

STATE_FILE = "seen_alerts.json"
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")
HEADERS = {"User-Agent": "ArchitectVulnRadar/1.0"}

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
        print(message)

def check_cisa_kev(seen):
    try:
        url = "https://cisa.gov"
        data = requests.get(url, headers=HEADERS, timeout=20).json()
        for v in data.get("vulnerabilities", []):
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
            seen.add(uid)
        print("CISA KEV check completed.")
    except Exception as e:
        print(f"CISA KEV check skipped due to error: {e}")

def check_palo_alto(seen):
    try:
        url = "https://paloaltonetworks.com"
        data = requests.get(url, headers=HEADERS, timeout=20).json()
        for item in data[:25]:
            cve = item.get("id", "")
            uid = f"PAN-{cve}"
            if uid in seen or not cve:
                continue
            send_alert(
                "Palo Alto PSIRT",
                f"{cve}: {item.get('title', 'Advisory')}",
                f"Severity: {item.get('severity')} | Affected: {', '.join(item.get('affected', []))}",
                f"https://paloaltonetworks.com{cve}"
            )
            seen.add(uid)
        print("Palo Alto check completed.")
    except Exception as e:
        print(f"Palo Alto check skipped due to error: {e}")

def check_github_advisories(seen):
    try:
        url = "https://github.com"
        gh_headers = {"Accept": "application/vnd.github+json", "User-Agent": "ArchitectVulnRadar/1.0"}
        data = requests.get(url, headers=gh_headers, timeout=20).json()
        if not isinstance(data, list):
            return
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
            seen.add(uid)
        print("GitHub Advisories check completed.")
    except Exception as e:
        print(f"GitHub Advisories check skipped due to error: {e}")

def check_rss_feeds(seen):
    feeds = {
        "FortiGuard PSIRT": "https://fortinet.com",
        "INCIBE-CERT": "https://incibe.es"
    }
    for source_name, feed_url in feeds.items():
        try:
            resp = requests.get(feed_url, headers=HEADERS, timeout=20)
            parsed = feedparser.parse(resp.content)
            for entry in parsed.entries[:15]:
                uid = f"RSS-{entry.get('id', entry.get('link'))}"
                if uid in seen:
                    continue
                if source_name == "FortiGuard PSIRT" or matches_stack(entry.get("title", "") + entry.get("summary", "")):
                    send_alert(
                        source_name,
                        entry.get("title", "New Advisory"),
                        entry.get("summary", "")[:240] + "...",
                        entry.get("link", "")
                    )
                seen.add(uid)
            print(f"{source_name} check completed.")
        except Exception as e:
            print(f"{source_name} check skipped due to error: {e}")

def main():
    seen = load_seen()
    check_cisa_kev(seen)
    check_palo_alto(seen)
    check_github_advisories(seen)
    check_rss_feeds(seen)
    save_seen(seen)
    print("Radar scan finished cleanly.")

if __name__ == "__main__":
    main()
