import json
import os
from datetime import datetime, timedelta, timezone
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

def check_palo_alto_official(seen):
    try:
        # Official Palo Alto PSIRT JSON endpoint
        url = "https://security.paloaltonetworks.com/json?severity=CRITICAL&severity=HIGH&sort=-updated"
        headers = {"Accept": "application/json", "User-Agent": "Mozilla/5.0"}
        resp = requests.get(url, headers=headers, timeout=20)
        if resp.status_code != 200 or not resp.text.strip().startswith("["):
            print(f"Palo Alto JSON status: {resp.status_code}")
            return
        items = resp.json()
        sent = 0
        for item in items[:20]:
            cve = item.get("id", "")
            uid = f"PAN-{cve}"
            if uid in seen or not cve:
                continue
            affected = ", ".join(item.get("affected", [])) or "PAN-OS / Palo Alto"
            send_alert(
                "Palo Alto Networks PSIRT",
                f"{cve}: {item.get('title', 'Security Advisory')}",
                f"Severity: {item.get('severity')} | Affected: {affected}",
                f"https://security.paloaltonetworks.com/{cve}"
            )
            seen.add(uid)
            sent += 1
        print(f"Palo Alto PSIRT check completed. Sent {sent} alerts.")
    except Exception as e:
        print(f"Palo Alto PSIRT error: {e}")

def check_nvd_api_v2(seen):
    try:
        # Official NIST NVD API 2.0 (Last 72h) - covers Check Point, Zscaler, Fortinet, AI/MCP, Cloud, Financial
        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=72)).strftime("%Y-%m-%dT%H:%M:%S.000")
        end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
        url = "https://nist.gov"
        params = {"pubStartDate": start, "pubEndDate": end, "resultsPerPage": 150}
        resp = requests.get(url, params=params, headers={"User-Agent": "python-requests/2.31"}, timeout=30)
        if resp.status_code != 200:
            print(f"NVD API v2 HTTP {resp.status_code}")
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
                    "NVD CVE Alert (Check Point / Zscaler / AI / Cloud)",
                    cve_id,
                    desc_text[:280] + "...",
                    f"https://nist.gov{cve_id}"
                )
                sent += 1
            seen.add(uid)
        print(f"NVD API v2 check completed. Scanned {len(items)} CVEs, sent {sent} alerts.")
    except Exception as e:
        print(f"NVD API v2 error: {e}")

def check_first_epss(seen):
    try:
        # FIRST EPSS API - flags CVEs with >60% real-world exploit probability
        url = "https://first.org"
        resp = requests.get(url, headers={"User-Agent": "python-requests/2.31"}, timeout=20)
        if resp.status_code != 200:
            print(f"EPSS API HTTP {resp.status_code}")
            return
        items = resp.json().get("data", [])
        sent = 0
        for item in items:
            cve_id = item.get("cve", "")
            uid = f"EPSS-{cve_id}"
            if uid in seen or not cve_id:
                continue
            # Check NVD detail for matching vendor before alerting
            nvd_resp = requests.get(f"https://nist.gov?cveId={cve_id}", timeout=15)
            if nvd_resp.status_code == 200:
                vulns = nvd_resp.json().get("vulnerabilities", [])
                if vulns:
                    descs = vulns.get("cve", {}).get("descriptions", [])
                    desc_text = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                    if matches_stack(desc_text):
                        score_pct = round(float(item.get("epss", 0)) * 100, 1)
                        send_alert(
                            f"HIGH EXPLOIT PROBABILITY (EPSS {score_pct}%)",
                            cve_id,
                            desc_text[:260] + "...",
                            f"https://nist.gov{cve_id}"
                        )
                        sent += 1
            seen.add(uid)
        print(f"FIRST EPSS check completed. Sent {sent} alerts.")
    except Exception as e:
        print(f"FIRST EPSS error: {e}")

def check_rss_feeds(seen):
    feeds = {
        "FortiGuard PSIRT": "https://fortiguard.fortinet.com/rss/ir.xml",
        "CISA Advisories & KEV": "https://cisa.gov",
        "Unit 42 (Palo Alto Threat Intel)": "https://paloaltonetworks.com",
        "BleepingComputer": "https://bleepingcomputer.com",
        "The Hacker News": "https://feedburner.com"
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
                if source_name in ["FortiGuard PSIRT", "CISA Advisories & KEV", "Unit 42 (Palo Alto Threat Intel)"] or matches_stack(text_blob):
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
    check_palo_alto_official(seen)
    check_nvd_api_v2(seen)
    check_first_epss(seen)
    check_rss_feeds(seen)
    save_seen(seen)
    print("Radar scan finished cleanly.")

if __name__ == "__main__":
    main()
