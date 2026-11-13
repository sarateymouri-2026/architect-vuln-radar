import base64
import json
import os
import re
import certifi
import requests
import feedparser

STATE_FILE = "seen_alerts.json"
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")
TEST_MODE = os.environ.get("TEST_MODE", "false").lower() == "true"

# Enforce strict CA certificate verification via certifi
session = requests.Session()
session.verify = certifi.where()

# Tailored Architect Stack: SASE, NGFW, NAC, Cloud/Identity, AI/MCP & Financial
KEYWORDS = [
    # SASE & Zero Trust
    "zscaler", "zia", "zpa", "client connector", "zdx",
    "prisma access", "prisma sase", "fortisase", "harmony sase", "harmony connect",
    # NGFW, VPN & NAC
    "palo alto", "pan-os", "panorama", "globalprotect",
    "fortinet", "fortigate", "fortios", "fortimanager", "fortianalyzer", "fortiproxy",
    "check point", "checkpoint", "quantum", "gaia", "smartconsole",
    "cisco ise", "identity services engine", "cisco asa", "ftd", "firepower",
    # Microsoft Cloud, Identity & Infrastructure
    "azure", "entra", "active directory", "exchange", "sharepoint", "ad fs",
    "mcp gateway", "agents sdk", "openai", "copilot", "kubernetes", "devops",
    "dns server", "dhcp server", "rd gateway", "remote desktop gateway", "rras", "nps",
    # AWS, AI/MCP & CI/CD
    "aws", "amazon web services", "mcp", "model context protocol", "langchain",
    "gitlab", "github", "terraform", "docker", "argocd",
    # Financial / EU Core
    "swift", "dora", "weblogic", "oracle", "sap", "f5", "big-ip", "ivanti", "citrix", "netscaler"
]

def decode_url(b64_str):
    return base64.b64decode(b64_str).decode("utf-8")

def clean_html(raw_html):
    text = re.sub(r"<[^>]+>", " ", raw_html or "")
    return re.sub(r"\s+", " ", text).strip()

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

def get_architect_action(text_blob):
    t = text_blob.lower()
    if any(k in t for k in ["zscaler", "zia", "zpa", "prisma access", "fortisase", "harmony"]):
        return "Verify SASE tunnel posture, ZPA App Connector versions, and Client Connector update rings."
    if any(k in t for k in ["pan-os", "globalprotect", "fortigate", "fortios", "check point", "gaia", "asa", "ftd", "firepower"]):
        return "Restrict external management plane access, inspect VPN portals, and apply IPS virtual patches."
    if any(k in t for k in ["ise", "entra", "azure", "active directory", "ad fs", "exchange", "nps"]):
        return "Audit Conditional Access / RADIUS policies, administrative RBAC roles, and out-of-band patches."
    if any(k in t for k in ["mcp", "agents sdk", "openai", "copilot", "kubernetes", "terraform", "gitlab", "github"]):
        return "Audit MCP gateway/server permissions, AI agent token scopes, and CI/CD runner secrets."
    return "Assess exposure across perimeter, SASE, and cloud control planes; coordinate urgent patch window."

def send_architect_report(category, source, title, impact, action, link):
    if not WEBHOOK_URL:
        return
    if not WEBHOOK_URL.startswith("https://"):
        raise ValueError("Security Policy Violation: WEBHOOK_URL must use HTTPS/TLS.")
    message = (
        f"🛡️ *[{category}] — {source}*\n"
        f"*Advisory:* <{link}|{title}>\n"
        f"*Architectural Impact:* {impact}\n"
        f"*Recommended Action:* {action}"
    )
    try:
        resp = session.post(WEBHOOK_URL, json={"text": message}, timeout=15)
        print(f"Slack delivered ({resp.status_code}): {title[:55]}")
    except Exception as e:
        print(f"Slack post failed: {e}")

def check_cisa_kev(seen):
    try:
        url = decode_url("aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2Npc2Fnb3Yva2V2LWRhdGEvbWFpbi9rbm93bl9leHBsb2l0ZWRfdnVsbmVyYWJpbGl0aWVzLmpzb24=")
        resp = session.get(url, timeout=20)
        if resp.status_code != 200:
            print(f"CISA KEV HTTP {resp.status_code}")
            return
        vulns = resp.json().get("vulnerabilities", [])
        vulns_sorted = sorted(vulns, key=lambda x: x.get("dateAdded", ""), reverse=True)[:50]
        sent = 0
        for v in vulns_sorted:
            cve_id = v.get("cveID", "")
            uid = f"KEV-{cve_id}"
            blob = f"{v.get('vendorProject', '')} {v.get('product', '')} {v.get('vulnerabilityName', '')}"
            if not matches_stack(blob):
                continue
            if uid not in seen or (TEST_MODE and sent < 2):
                cve_base = decode_url("aHR0cHM6Ly93d3cuY3ZlLm9yZy9DVkVSZWNvcmQ/aWQ9")
                send_architect_report(
                    "ACTIVE EXPLOIT (CISA KEV)",
                    f"{v.get('vendorProject')} {v.get('product')}",
                    f"{cve_id}: {v.get('vulnerabilityName')}",
                    f"Confirmed exploitation in the wild (Added: {v.get('dateAdded')}).",
                    f"{v.get('requiredAction')} (Due: {v.get('dueDate')}).",
                    f"{cve_base}{cve_id}"
                )
                sent += 1
            seen.add(uid)
        print(f"CISA KEV check completed (scanned {len(vulns)} total). Sent {sent} alerts.")
    except Exception as e:
        print(f"CISA KEV error: {e}")

def check_osv_ai_cloud(seen):
    try:
        api_url = decode_url("aHR0cHM6Ly9hcGkub3N2LmRldi92MS9xdWVyeQ==")
        osv_base = decode_url("aHR0cHM6Ly9vc3YuZGV2L3Z1bG5lcmFiaWxpdHkv")
        packages = [
            ("PyPI", "mcp"),
            ("PyPI", "langchain-core"),
            ("npm", "@modelcontextprotocol/sdk"),
            ("Go", "k8s.io/kubernetes")
        ]
        sent = 0
        for eco, pkg in packages:
            resp = session.post(api_url, json={"package": {"ecosystem": eco, "name": pkg}}, timeout=15)
            if resp.status_code != 200:
                continue
            vulns = resp.json().get("vulns", [])[-3:]
            for v in vulns:
                vid = v.get("id", "")
                uid = f"OSV-{vid}"
                if not vid:
                    continue
                if uid not in seen or (TEST_MODE and sent < 1):
                    summary = clean_html(v.get("summary") or v.get("details", "Vulnerability detected"))[:220]
                    send_architect_report(
                        "AI / MCP / CLOUD SUPPLY CHAIN",
                        f"OSV ({pkg})",
                        vid,
                        summary,
                        "Audit MCP server permissions, AI agent dependencies, and Kubernetes workloads.",
                        f"{osv_base}{vid}"
                    )
                    sent += 1
                seen.add(uid)
        print(f"OSV AI/MCP/Cloud check completed. Sent {sent} alerts.")
    except Exception as e:
        print(f"OSV error: {e}")

def check_rss_feeds(seen):
    feeds = [
        ("MICROSOFT CLOUD & INFRA", "Microsoft MSRC", "aHR0cHM6Ly9hcGkubXNyYy5taWNyb3NvZnQuY29tL3VwZGF0ZS1ndWlkZS9yc3M=", False),
        ("NGFW & SASE PSIRT", "Palo Alto Networks PSIRT", "aHR0cHM6Ly9zZWN1cml0eS5wYWxvYWx0b25ldHdvcmtzLmNvbS9yc3MueG1s", True),
        ("NGFW & SASE PSIRT", "FortiGuard PSIRT", "aHR0cHM6Ly9maWxlc3RvcmUuZm9ydGluZXQuY29tL2ZvcnRpZ3VhcmQvcnNzL2lyLnhtbA==", True),
        ("NGFW & SASE RESEARCH", "Check Point Research", "aHR0cHM6Ly9yZXNlYXJjaC5jaGVja3BvaW50LmNvbS9jYXRlZ29yeS90aHJlYXQtaW50ZWxsaWdlbmNlLXJlcG9ydHMvZmVlZC8=", True),
        ("NAC & FIREWALL PSIRT", "Cisco Security Advisories", "aHR0cHM6Ly9zZWMuY2xvdWRhcHBzLmNpc2NvLmNvbS9zZWN1cml0eS9jZW50ZXIvcHNpcnRyc3MyMC9DaXNjb1NlY3VyaXR5QWR2aXNvcnkueG1s", False),
        ("THREAT INTELLIGENCE", "Palo Alto Unit 42", "aHR0cHM6Ly91bml0NDIucGFsb2FsdG9uZXR3b3Jrcy5jb20vZmVlZC8=", True),
        ("SPAIN / EU CERT", "INCIBE-CERT", "aHR0cHM6Ly93d3cuaW5jaWJlLmVzL2luY2liZS1jZXJ0L2FsZXJ0YS10ZW1wcmFuYS9hdmlzb3MvZmVlZA==", False),
        ("ZERO-DAYS & ZSCALER/CP INTEL", "The Hacker News", "aHR0cHM6Ly9mZWVkcy5mZWVkYnVybmVyLmNvbS9UaGVIYWNrZXJzTmV3cw==", False),
        ("SASE & BREACH INTEL", "BleepingComputer", "aHR0cHM6Ly93d3cuYmxlZXBpbmdjb21wdXRlci5jb20vZmVlZC8=", False)
    ]
    for category, source_name, b64_url, is_direct_vendor in feeds:
        try:
            feed_url = decode_url(b64_url)
            resp = session.get(feed_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=25)
            parsed = feedparser.parse(resp.content)
            limit = 60 if "Microsoft MSRC" in source_name else 15
            entries = parsed.entries[:limit]
            sent = 0
            for entry in entries:
                uid = f"RSS-{entry.get('id', entry.get('link'))}"
                title = clean_html(entry.get("title", "New Advisory"))
                summary = clean_html(entry.get("summary", ""))
                text_blob = f"{title} {summary}"

                if "Microsoft MSRC" in source_name and "informational change only" in summary.lower():
                    seen.add(uid)
                    continue

                if "Palo Alto" in source_name and "(Severity: LOW)" in title:
                    seen.add(uid)
                    continue

                if not is_direct_vendor and not matches_stack(text_blob):
                    seen.add(uid)
                    continue

                if uid not in seen or (TEST_MODE and sent < 1 and ("Microsoft MSRC" in source_name or is_direct_vendor)):
                    impact_text = summary[:220] + "..." if summary else "Official vendor advisory published."
                    action_text = get_architect_action(text_blob)
                    send_architect_report(category, source_name, title, impact_text, action_text, entry.get("link", ""))
                    sent += 1
                seen.add(uid)
            print(f"{source_name} check completed (parsed {len(entries)} items). Sent {sent} alerts.")
        except Exception as e:
            print(f"{source_name} skipped: {e}")

def main():
    print(f"Starting Architect Radar Scan (TEST_MODE={TEST_MODE})...")
    seen = load_seen()
    check_cisa_kev(seen)
    check_osv_ai_cloud(seen)
    check_rss_feeds(seen)
    save_seen(seen)
    print("Radar scan finished cleanly.")

if __name__ == "__main__":
    main()
