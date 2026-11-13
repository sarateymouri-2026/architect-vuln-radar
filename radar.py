import base64
import json
import os
import re
from datetime import datetime, timezone
import certifi
import requests
import feedparser

STATE_FILE = "seen_alerts.json"
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")
TEST_MODE = os.environ.get("TEST_MODE", "false").lower() == "true"

session = requests.Session()
session.verify = certifi.where()

STATS = {"critical": 0, "vendor": 0, "ai_cloud": 0}

KEYWORDS = [
    "zscaler", "zia", "zpa", "client connector", "zdx",
    "prisma access", "prisma sase", "fortisase", "harmony sase", "harmony connect",
    "palo alto", "pan-os", "panorama", "globalprotect",
    "fortinet", "fortigate", "fortios", "fortimanager", "fortianalyzer", "fortiproxy",
    "check point", "checkpoint", "quantum", "gaia", "smartconsole",
    "cisco ise", "identity services engine", "cisco asa", "ftd", "firepower",
    "azure", "entra", "active directory", "exchange", "sharepoint", "ad fs",
    "mcp gateway", "agents sdk", "openai", "copilot", "kubernetes", "devops",
    "dns server", "dhcp server", "rd gateway", "remote desktop gateway", "rras", "nps",
    "aws", "amazon web services", "mcp", "model context protocol", "langchain",
    "gitlab", "github", "terraform", "docker", "argocd",
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

    cat_upper = category.upper()
    if "ACTIVE EXPLOIT" in cat_upper or "ZERO-DAY" in cat_upper:
        color = "#E01E5A"
        badge = "🔴 CRITICAL / ACTIVE EXPLOIT"
        STATS["critical"] += 1
    elif "AI / MCP" in cat_upper or "SUPPLY CHAIN" in cat_upper:
        color = "#9B59B6"
        badge = "🟣 AI / MCP / CLOUD"
        STATS["ai_cloud"] += 1
    else:
        color = "#ECB22E"
        badge = "🟠 VENDOR / SASE / NGFW"
        STATS["vendor"] += 1

    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "context",
                        "elements": [{"type": "mrkdwn", "text": f"*{badge}*  |  *Source:* {source}"}]
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*<{link}|{title}>*\n{impact}"}
                    },
                    {
                        "type": "context",
                        "elements": [{"type": "mrkdwn", "text": f"🛠️ *Architect Action:* {action}"}]
                    }
                ]
            }
        ]
    }
    try:
        resp = session.post(WEBHOOK_URL, json=payload, timeout=15)
        print(f"Slack delivered ({resp.status_code}): {title[:55]}")
    except Exception as e:
        print(f"Slack post failed: {e}")

def send_dashboard_summary():
    total = STATS["critical"] + STATS["vendor"] + STATS["ai_cloud"]
    if total == 0 or not WEBHOOK_URL:
        return
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    payload = {
        "attachments": [
            {
                "color": "#2EB67D",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"📊 *Architect Radar Scan Summary* ({now_utc})\n"
                                f"• 🔴 *Critical / Active Exploits:* {STATS['critical']}\n"
                                f"• 🟠 *NGFW / SASE / Infra Advisories:* {STATS['vendor']}\n"
                                f"• 🟣 *AI / MCP / Cloud Supply Chain:* {STATS['ai_cloud']}"
                            )
                        }
                    }
                ]
            }
        ]
    }
    try:
        session.post(WEBHOOK_URL, json=payload, timeout=15)
        print("Dashboard summary card delivered.")
    except Exception as e:
        print(f"Summary post failed: {e}")

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
