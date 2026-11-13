# architect-vuln-radar
Architect-Vuln-Radar
# 🛡️ Architect Vulnerability Radar

An automated, zero-cost threat intelligence and vulnerability radar built for **Information Security Architects** and **Network Security Architects**. 

Instead of waiting for SOC escalations or drowning in raw CVE firehoses, this GitHub Actions pipeline polls high-signal vendor PSIRTs, active exploitation catalogs, and AI/Cloud supply chain feeds every hour—delivering color-coded **Architect Security Report Cards** with immediate containment guidance straight to Slack.

---

## 🎯 What It Monitors

* **Active Exploitation:** CISA Known Exploited Vulnerabilities (KEV) catalog.
* **SASE & Zero Trust:** Zscaler (ZIA, ZPA, Client Connector, ThreatLabz), Prisma Access, FortiSASE, Harmony SASE.
* **Next-Gen Firewalls, VPN & NAC:** Palo Alto Networks (PAN-OS, Panorama, GlobalProtect, Unit 42), Fortinet (FortiGate, FortiOS, FortiManager), Check Point (Quantum, Gaia, Research), Cisco (ISE, ASA, FTD, Firepower).
* **Cloud & Identity Plane:** Microsoft MSRC (filtered to Azure, Entra ID, Active Directory, Exchange, Windows Server, MCP Gateway), AWS, Okta.
* **AI, MCP & CI/CD Supply Chain:** Google OSV.dev API tracking Model Context Protocol (`mcp`, `@modelcontextprotocol/sdk`), `langchain-core`, `kubernetes`, Terraform, and GitLab/GitHub CI.
* **Zero-Day & Perimeter Intel:** Keyword-filtered alerts from *The Hacker News* and *BleepingComputer*.

---

## 📊 Slack Dashboard Cards

Every matching advisory is delivered as a color-coded Slack Block Kit card with tailored architectural containment actions:

* 🔴 **Red — Critical / Active Exploit:** Confirmed in-the-wild exploitation (CISA KEV) and active perimeter zero-days.
* 🟠 **Orange — Vendor / SASE / NGFW:** High/Critical vendor PSIRT advisories and infrastructure security updates.
* 🟣 **Purple — AI / MCP / Cloud:** Emerging supply chain vulnerabilities across agentic AI frameworks and container orchestration.
* 🟢 **Green — Scan Summary:** Executive rollup posted automatically whenever new findings are detected.

---

## 🚀 Quick Setup (2 Minutes)

### 1. Fork This Repository
Click **Fork** in the top-right corner of this repository to copy it to your own GitHub account. *(GitHub Actions is completely free and unlimited for public repositories.)*

### 2. Create a Slack Incoming Webhook
1. Open the [Slack API Apps Portal](https://slack.com) and click **Create New App** > **From scratch** (or **Pick features**).
2. Enable **Incoming Webhooks** (or add the `incoming-webhook` scope) and install the app to your desired Slack channel (e.g., `#secarch-intel`).
3. Copy your generated Webhook URL (`https://slack.com...`).

### 3. Add Your Webhook Secret in GitHub
1. In your forked repository, go to **Settings** > **Secrets and variables** > **Actions**.
2. Click **New repository secret**.
3. Set **Name** to `WEBHOOK_URL` and paste your Slack webhook URL into **Secret**, then click **Add secret**.

### 4. Run Your First Scan
1. Go to the **Actions** tab in your repository and enable workflows if prompted.
2. Select **Architect Vulnerability Radar** on the left sidebar and click **Run workflow** (leave `test_mode` set to `true` to verify immediate Slack delivery).
3. From this point forward, the radar runs automatically **every hour** (`cron: '23 * * * *'`), staying silent until a brand-new matching advisory is published.

---

## ⚙️ Customization

Open `radar.py` to tailor the radar to your environment:
* **Vendor & Stack Keywords:** Edit the `KEYWORDS` list to add or remove specific products, cloud services, or middleware.
* **Architectural Playbooks:** Update `get_architect_action()` to customize the recommended containment steps shown on your Slack cards.
* **Scan Schedule:** Edit the `cron` expression in `.github/workflows/radar.yml` to change how frequently the radar polls feeds.

---

## 🔒 Security Design

* **Zero Secrets in Code:** All webhook credentials are stored encrypted via GitHub Actions Secrets and validated to enforce `HTTPS/TLS`.
* **Certificate Verification:** Enforces strict X.509 certificate validation via `certifi`.
* **Stateless Git History:** Uses `actions/cache@v4` to persist deduplication state (`seen_alerts.json`) without cluttering commit history.
