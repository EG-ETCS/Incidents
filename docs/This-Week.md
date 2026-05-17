---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![Cisco](2026/Week20/images/Cisco.png)

    **Cisco Catalyst SD-WAN Zero-Day Vulnerability - CVE-2026-20182**

    **CVE-2026-20182**{.cve-chip} **Cisco SD-WAN**{.cve-chip} **Zero-Day**{.cve-chip} **Authentication Bypass**{.cve-chip}

    Cisco patched a critical zero-day in Catalyst SD-WAN peering authentication where crafted DTLS traffic to the `vdaemon` service can impersonate trusted peers and bypass authentication.

    Successful exploitation can grant privileged administrative control, enabling SSH key abuse, NETCONF tampering, privilege escalation, and persistent access across enterprise WAN environments.

    [Read more](2026/Week20/Cisco.md)

-   ![Microsoft](2026/Week20/images/Microsoft.png)

    **Microsoft Exchange Server Cross-Site Scripting (XSS) Vulnerability - CVE-2026-42897**

    **CVE-2026-42897**{.cve-chip} **Microsoft Exchange**{.cve-chip} **OWA XSS**{.cve-chip} **Active Exploitation**{.cve-chip}

    A vulnerability in Exchange OWA input handling can allow crafted email content to execute attacker-controlled JavaScript in authenticated browser sessions.

    Exploitation may enable session hijacking, mailbox impersonation, internal phishing, and broader business email compromise risk in on-prem Exchange deployments.

    [Read more](2026/Week20/Microsoft.md)

</div>
