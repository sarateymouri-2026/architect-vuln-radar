import json
import os
import re
import requests
import feedparser

STATE_FILE = "seen_alerts.json"
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")
TEST_MODE = os.environ.get("TEST_MODE", "false").lower() == "true"

# Precision-Tuned for Your Exact Architecture Stack
KEYWORDS = [
    # SASE & Zero Trust
    "zscaler", "zia", "zpa", "client connector", "zdx",
    "prisma access", "prisma sase", "fortisase", "harmony sase", "harmony connect",
    # NGFW, VPN & Network Access Control
    "palo alto", "pan-os", "panorama", "globalprotect",
    "fortinet", "fortigate", "fortios", "fortimanager", "fortianalyzer", "fortiproxy",
    "check point", "checkpoint", "quantum", "gaia", "smartconsole",
    "cisco ise", "identity services engine", "cisco asa", "adaptive security appliance", "ftd", "firepower",
    # Cloud & Identity Plane
    "aws", "amazon web services", "azure", "entra", "entra id", "active directory", "okta",
    # AI, MCP & CI/CD Pipelines
    "mcp", "model context protocol", "langchain", "openai", "anthropic", "agentic",
    "gitlab", "github", "terraform", "kubernetes", "docker", "argocd",
    # Financial / EU DORA Core
    "swift", "dora", "weblogic", "oracle", "sap", "f5", "big-ip", "ivanti", "citrix", "netscaler"
]

def build_url(scheme, host, path):
    return f"{scheme}://{host}{path}"

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
        return "Verify SASE tunnel posture, ZPA App Connector versions, and Client Connector auto-update rings."
    if any(k in t for k in ["pan-os", "globalprotect", "fortigate", "fortios", "check point", "gaia", "asa", "ftd", "firepower"]):
        return "Restrict external management plane access, inspect SSL-VPN/GlobalProtect portals, and apply IPS virtual patches."
    if any(k in t for k in ["ise", "identity services", "entra", "azure", "aws"]):
        return "Audit Conditional Access / RADIUS policies, administrative RBAC roles, and API token scopes."
    if any(k in t for k in ["mcp", "model context", "langchain", "kubernetes", "terraform", "gitlab", "github"]):
        return "Audit MCP server tool permissions, CI/CD runner secrets, and container base images."
    return "Assess exposure across perimeter, SASE, and cloud control planes; coordinate urgent patch window."

def send_architect_report(category, source, title, impact, action, link):
    message = (
        f"🛡️ *[{category}] — {source}*\n"
        f"*Advisory:* <{link}|{title}>\n"
        f"*Architectural Impact:* {impact}\n"
        f"*Recommended Action:* {action}"
    )
    if WEBHOOK_URL:
        try:
            resp = requests.post(WEBHOOK_URL, json={"text": message}, timeout=15)
            print(f"Slack delivered ({resp.status_code}): {title[:55]}")
        except Exception as e:
            print(f"Slack post failed: {e}")

def check_cisa_kev(seen):
    try:
        url = build_url("https", "://githubusercontent.com", "/cisagov/kev-data/main/known_exploited_vulnerabilities.json")
        resp = requests.get(url, timeout=20)
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
                cve_link = build_url("https", "www.cve.org", f"/CVERecord?id={cve_id}")
                send_architect_report(
                    "ACTIVE EXPLOIT (CISA KEV)",
                    f"{v.get('vendorProject')} {v.get('product')}",
                    f"{cve_id}: {v.get('vulnerabilityName')}",
                    f"Confirmed exploitation in the wild (Added: {v.get('dateAdded')}).",
                    f"{v.get('requiredAction')} (Due: {v.get('dueDate')}).",
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
            ("PyPI", "langchain-core"),
            ("npm", "@modelcontextprotocol/sdk"),
            ("Go", "k8s.io/kubernetes")
        ]
        sent = 0
        for eco, pkg in packages:
            resp = requests.post(api_url, json={"package": {"ecosystem": eco, "name": pkg}}, timeout=15)
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
                    osv_link = build_url("https", "osv.dev", f"/vulnerability/{vid}")
                    send_architect_report(
                        "AI / MCP / CLOUD SUPPLY CHAIN",
                        f"OSV ({pkg})",
                        vid,
                        summary,
                        "Audit MCP server permissions, AI agent dependencies, and Kubernetes workloads.",
                        osv_link
                    )
                    sent += 1
                seen.add(uid)
        print(f"OSV AI/MCP/Cloud check completed. Sent {sent} alerts.")
    except Exception as e:
        print(f"OSV error: {e}")

def check_rss_feeds(seen):
    # Format: (Category, Source Name, Host, Path, Direct Vendor Flag)
    feeds = [
        ("SASE & ZTNA", "Zscaler Help & Advisories", "help.zscaler.com", "/rss", True),
        ("SASE & CLOUD TRUST", "Zscaler Trust", "trust.zscaler.com", "/rss", True),
        ("NGFW & SASE RESEARCH", "Check Point Research", "://checkpoint.com", "/feed/", True),
        ("NGFW & SASE PSIRT", "Palo Alto Networks PSIRT", "://paloaltonetworks.com", "/rss.xml", True),
        ("NGFW & SASE PSIRT", "FortiGuard PSIRT", "://fortinet.com", "/rss/ir.xml", True),
        ("NAC & FIREWALL PSIRT", "Cisco Security Advisories", "://cisco.com", "/security/center/psirtrss20/CiscoSecurityAdvisory.xml", True),
        ("GOVERNMENT & INFRA", "CISA Advisories", "www.cisa.gov", "/cybersecurity-advisories/all.xml", True),
        ("THREAT INTELLIGENCE", "Palo Alto Unit 42", "://paloaltonetworks.com", "/feed/", True),
        ("ZERO-DAYS & CLOUD INTEL", "The Hacker News", "://feedburner.com", "/TheHackersNews", False),
        ("SASE & BREACH INTEL", "BleepingComputer", "://bleepingcomputer.com", "/feed/", False),
        ("FINANCIAL & ENTERPRISE", "SecurityWeek", "://feedburner.com", "/securityweek", False)
    ]
    for category, source_name, host, path, is_direct_vendor in feeds:
        try:
            feed_url = build_url("https", host, path)
            resp = requests.get(feed_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=20)
            parsed = feedparser.parse(resp.content)
            entries = parsed.entries[:15]
            sent = 0
            for entry in entries:
                uid = f"RSS-{entry.get('id', entry.get('link'))}"
                title = clean_html(entry.get("title", "New Advisory"))
                summary = clean_html(entry.get("summary", ""))
                text_blob = f"{title} {summary}"

                # Skip LOW severity noise from Palo Alto
                if "Palo Alto" in source_name and "(Severity: LOW)" in title:
                    seen.add(uid)
                    continue

                # For broad Cisco feed, filter to ISE / ASA / FTD / Firepower / IOS XE so you don't get VoIP phone noise
                if "Cisco" in source_name and not matches_stack(text_blob):
                    seen.add(uid)
                    continue

                if not is_direct_vendor and not matches_stack(text_blob):
                    continue

                if uid not in seen or (TEST_MODE and sent < 1 and is_direct_vendor):
                    impact_text = summary[:220] + "..." if summary else "Official vendor advisory published for your SASE/Firewall/Cloud stack."
                    action_text = get_architect_action(text_blob)
                    send_architect_report(
                        category,
                        source_name,
                        title,
                        impact_text,
                        action_text,
                        entry.get("link", "")
                    )
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
