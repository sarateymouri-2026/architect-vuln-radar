def check_rss_feeds(seen):
    feeds = [
        ("Palo Alto Networks PSIRT", "security.paloaltonetworks.com", "/rss.xml", True),
        ("FortiGuard PSIRT", "://fortinet.com", "/rss/ir.xml", True),
        ("Cisco Security Advisories", "://cisco.com", "/security/center/psirtrss20/CiscoSecurityAdvisory.xml", True),
        ("CISA Advisories", "www.cisa.gov", "/cybersecurity-advisories/all.xml", True),
        ("Unit 42 (Palo Alto Intel)", "unit42.paloaltonetworks.com", "/feed/", True),
        ("The Hacker News (Check Point/Zscaler/Zero-Days)", "://feedburner.com", "/TheHackersNews", False),
        ("BleepingComputer (SASE/Firewalls/Breaches)", "://bleepingcomputer.com", "/feed/", False),
        ("SecurityWeek (Enterprise/Financial/ICS)", "://feedburner.com", "/securityweek", False)
    ]
    for source_name, host, path, is_direct_vendor in feeds:
        try:
            feed_url = build_url("https", host, path)
            resp = requests.get(feed_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=20)
            parsed = feedparser.parse(resp.content)
            entries = parsed.entries[:15]
            sent = 0
            for entry in entries:
                uid = f"RSS-{entry.get('id', entry.get('link'))}"
                title = entry.get("title", "New Advisory")
                summary = entry.get("summary", "")
                text_blob = f"{title} {summary}"
                # Skip LOW severity noise from Palo Alto RSS
                if "Palo Alto" in source_name and "(Severity: LOW)" in title:
                    seen.add(uid)
                    continue
                if not is_direct_vendor and not matches_stack(text_blob):
                    continue
                if uid not in seen or (TEST_MODE and sent < 1 and is_direct_vendor):
                    send_alert(
                        source_name,
                        title,
                        summary[:240] + "..." if summary else "Click link to view full vendor advisory.",
                        entry.get("link", "")
                    )
                    sent += 1
                seen.add(uid)
            print(f"{source_name} check completed (parsed {len(entries)} items). Sent {sent} alerts.")
        except Exception as e:
            print(f"{source_name} skipped: {e}")
