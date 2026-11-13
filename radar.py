import base64, json, os, re
from datetime import datetime, timezone
import certifi, requests, feedparser

STATE_FILE = "seen_alerts.json"
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")
TEST_MODE = os.environ.get("TEST_MODE", "false").lower() == "true"

session = requests.Session()
session.verify = certifi.where()
STATS = {"critical": 0, "vendor": 0, "ai_cloud": 0}

KEYWORDS = [
    "zscaler", "zia", "zpa", "client connector", "prisma access", "prisma sase", "fortisase", "harmony sase",
    "palo alto", "pan-os", "panorama", "globalprotect", "fortinet", "fortigate", "fortios", "fortimanager",
    "check point", "checkpoint", "quantum", "gaia", "cisco ise", "cisco asa", "ftd", "firepower",
    "azure", "entra", "active directory", "exchange", "sharepoint", "ad fs", "mcp gateway", "agents sdk",
    "openai", "copilot", "kubernetes", "devops", "aws", "mcp", "model context protocol", "langchain",
    "gitlab", "github", "terraform", "docker", "argocd", "swift", "dora", "weblogic", "oracle", "sap",
    "f5", "big-ip", "ivanti", "citrix", "netscaler"
]

def dec(s):
    return base64.b64decode(s).decode("utf-8")

def clean(t):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", t or "")).strip()

def load_seen():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return set(json.load(f))
    return set()

def save_seen(seen):
    with open(STATE_FILE, "w") as f:
        json.dump(sorted(list(seen)), f, indent=2)

def matches(text):
    tl = text.lower()
    return any(k in tl for k in KEYWORDS)

def get_action(blob):
    t = blob.lower()
    if any(k in t for k in ["zscaler", "zia", "zpa", "prisma", "fortisase", "harmony"]):
        return "Verify SASE tunnel posture, ZPA App Connectors, and Client Connector update rings."
    if any(k in t for k in ["pan-os", "globalprotect", "fortigate", "fortios", "check point", "gaia", "asa", "ftd"]):
        return "Restrict external management plane access, inspect VPN portals, and apply IPS virtual patches."
    if any(k in t for k in ["ise", "entra", "azure", "active directory", "ad fs", "exchange"]):
        return "Audit Conditional Access / RADIUS policies, RBAC roles, and out-of-band patches."
    if any(k in t for k in ["mcp", "agents sdk", "openai", "copilot", "kubernetes", "terraform", "gitlab"]):
        return "Audit MCP server permissions, AI agent token scopes, and CI/CD runner secrets."
    return "Assess exposure across perimeter, SASE, and cloud control planes; schedule urgent patch."

def send_card(cat, src, title, impact, action, link):
    if not WEBHOOK_URL:
        return
    if not WEBHOOK_URL.startswith("https://"):
        raise ValueError("WEBHOOK_URL must use HTTPS/TLS.")
    cu = cat.upper()
    if "ACTIVE EXPLOIT" in cu or "ZERO-DAY" in cu:
        color, badge = "#E01E5A", "🔴 CRITICAL / ACTIVE EXPLOIT"
        STATS["critical"] += 1
    elif "AI / MCP" in cu:
        color, badge = "#9B59B6", "🟣 AI / MCP / CLOUD"
        STATS["ai_cloud"] += 1
    else:
        color, badge = "#ECB22E", "🟠 VENDOR / SASE / NGFW"
        STATS["vendor"] += 1
    payload = {"attachments": [{"color": color, "blocks": [
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"*{badge}*  |  *Source:* {src}"}]},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*<{link}|{title}>*\n{impact}"}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"🛠️ *Architect Action:* {action}"}]}
    ]}]}
    try:
        r = session.post(WEBHOOK_URL, json=payload, timeout=15)
        print(f"Slack ({r.status_code}): {title[:55]}")
    except Exception as e:
        print(f"Slack error: {e}")

def send_summary():
    if sum(STATS.values()) == 0 or not WEBHOOK_URL:
        return
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    payload = {"attachments": [{"color": "#2EB67D", "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": (
        f"📊 *Architect Radar Summary* ({ts})\n"
        f"• 🔴 *Critical / Active Exploits:* {STATS['critical']}\n"
        f"• 🟠 *NGFW / SASE / Infra Advisories:* {STATS['vendor']}\n"
        f"• 🟣 *AI / MCP / Cloud Supply Chain:* {STATS['ai_cloud']}"
    )}}]}]}
    try:
        session.post(WEBHOOK_URL, json=payload, timeout=15)
    except Exception as e:
        print(f"Summary error: {e}")

def check_kev(seen):
    try:
        url = dec("aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2Npc2Fnb3Yva2V2LWRhdGEvbWFpbi9rbm93bl9leHBsb2l0ZWRfdnVsbmVyYWJpbGl0aWVzLmpzb24=")
        base = dec("aHR0cHM6Ly93d3cuY3ZlLm9yZy9DVkVSZWNvcmQ/aWQ9")
        vulns = sorted(session.get(url, timeout=20).json().get("vulnerabilities", []), key=lambda x: x.get("dateAdded", ""), reverse=True)[:50]
        sent = 0
        for v in vulns:
            cid = v.get("cveID", "")
            uid = f"KEV-{cid}"
            if not matches(f"{v.get('vendorProject')} {v.get('product')} {v.get('vulnerabilityName')}"):
                continue
            if uid not in seen or (TEST_MODE and sent < 2):
                send_card("ACTIVE EXPLOIT (CISA KEV)", f"{v.get('vendorProject')} {v.get('product')}", f"{cid}: {v.get('vulnerabilityName')}", f"Exploited in wild (Added: {v.get('dateAdded')}).", f"{v.get('requiredAction')} (Due: {v.get('dueDate')}).", f"{base}{cid}")
                sent += 1
            seen.add(uid)
        print(f"CISA KEV done. Sent {sent}.")
    except Exception as e:
        print(f"CISA KEV error: {e}")

def check_osv(seen):
    try:
        api = dec("aHR0cHM6Ly9hcGkub3N2LmRldi92MS9xdWVyeQ==")
        base = dec("aHR0cHM6Ly9vc3YuZGV2L3Z1bG5lcmFiaWxpdHkv")
        sent = 0
        for eco, pkg in [("PyPI", "mcp"), ("PyPI", "langchain-core"), ("npm", "@modelcontextprotocol/sdk"), ("Go", "k8s.io/kubernetes")]:
            r = session.post(api, json={"package": {"ecosystem": eco, "name": pkg}}, timeout=15)
            for v in r.json().get("vulns", [])[-3:]:
                vid = v.get("id", "")
                uid = f"OSV-{vid}"
                if vid and (uid not in seen or (TEST_MODE and sent < 1)):
                    send_card("AI / MCP SUPPLY CHAIN", f"OSV ({pkg})", vid, clean(v.get("summary") or v.get("details"))[:220], "Audit MCP permissions and AI/K8s dependencies.", f"{base}{vid}")
                    sent += 1
                seen.add(uid)
        print(f"OSV done. Sent {sent}.")
    except Exception as e:
        print(f"OSV error: {e}")

def check_rss(seen):
    feeds = [
        ("MICROSOFT INFRA", "Microsoft MSRC", "aHR0cHM6Ly9hcGkubXNyYy5taWNyb3NvZnQuY29tL3VwZGF0ZS1ndWlkZS9yc3M=", False),
        ("NGFW & SASE PSIRT", "Palo Alto PSIRT", "aHR0cHM6Ly9zZWN1cml0eS5wYWxvYWx0b25ldHdvcmtzLmNvbS9yc3MueG1s", True),
        ("NGFW & SASE PSIRT", "FortiGuard PSIRT", "aHR0cHM6Ly9maWxlc3RvcmUuZm9ydGluZXQuY29tL2ZvcnRpZ3VhcmQvcnNzL2lyLnhtbA==", True),
        ("NGFW & SASE INTEL", "Check Point Research", "aHR0cHM6Ly9yZXNlYXJjaC5jaGVja3BvaW50LmNvbS9jYXRlZ29yeS90aHJlYXQtaW50ZWxsaWdlbmNlLXJlcG9ydHMvZmVlZC8=", True),
        ("NAC & FIREWALL", "Cisco Security", "aHR0cHM6Ly9zZWMuY2xvdWRhcHBzLmNpc2NvLmNvbS9zZWN1cml0eS9jZW50ZXIvcHNpcnRyc3MyMC9DaXNjb1NlY3VyaXR5QWR2aXNvcnkueG1s", False),
        ("THREAT INTEL", "Palo Alto Unit 42", "aHR0cHM6Ly91bml0NDIucGFsb2FsdG9uZXR3b3Jrcy5jb20vZmVlZC8=", True),
        ("ZERO-DAY INTEL", "The Hacker News", "aHR0cHM6Ly9mZWVkcy5mZWVkYnVybmVyLmNvbS9UaGVIYWNrZXJzTmV3cw==", False),
        ("SASE & THREAT INTEL", "Zscaler ThreatLabz", "aHR0cHM6Ly93d3cuenNjYWxlci5jb20vYmxvZ3MvZmVlZHMvc2VjdXJpdHktcmVzZWFyY2g=", True),
        ("SASE & BREACHES", "BleepingComputer", "aHR0cHM6Ly93d3cuYmxlZXBpbmdjb21wdXRlci5jb20vZmVlZC8=", False)
    ]
    for cat, src, b64, direct in feeds:
        try:
            resp = session.get(dec(b64), headers={"User-Agent": "Mozilla/5.0"}, timeout=25)
            entries = feedparser.parse(resp.content).entries[:(60 if "MSRC" in src else 15)]
            sent = 0
            for e in entries:
                uid = f"RSS-{e.get('id', e.get('link'))}"
                title, summ = clean(e.get("title")), clean(e.get("summary"))
                blob = f"{title} {summ}"
                if ("MSRC" in src and "informational change only" in summ.lower()) or ("Palo Alto" in src and "(Severity: LOW)" in title):
                    seen.add(uid)
                    continue
                if not direct and not matches(blob):
                    seen.add(uid)
                    continue
                if uid not in seen or (TEST_MODE and sent < 1 and ("MSRC" in src or direct)):
                    send_card(cat, src, title, summ[:220] + "..." if summ else "Official vendor advisory.", get_action(blob), e.get("link", ""))
                    sent += 1
                seen.add(uid)
            print(f"{src}: {sent} alerts.")
        except Exception as ex:
            print(f"{src} skipped: {ex}")

def main():
    print(f"Radar Scan (TEST_MODE={TEST_MODE})")
    seen = load_seen()
    check_kev(seen)
    check_osv(seen)
    check_rss(seen)
    save_seen(seen)
    send_summary()
    print("Done.")

if __name__ == "__main__":
    main()
