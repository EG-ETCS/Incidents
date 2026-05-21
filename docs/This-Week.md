---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![Tp](2026/Week20/images/Tp.png)

    **TP-Link Archer AX53 Stack-Based Buffer Overflow - CVE-2026-30814**

    **CVE-2026-30814**{.cve-chip} **TP-Link**{.cve-chip} **Stack-Based Buffer Overflow**{.cve-chip} **Router Security**{.cve-chip}

    A high-severity stack-based buffer overflow in the `tmpServer` component of TP-Link Archer AX53 firmware (prior to 1.7.1 Build 20260213) allows an authenticated adjacent-network attacker to overflow stack memory via a crafted configuration payload, potentially enabling remote code execution, DNS hijacking, or denial of service.

    [Read more](2026/Week20/Tp.md)

-   ![GitHub](2026/Week20/images/GitHub.png)

    **GitHub Internal Repository Breach**

    **GitHub**{.cve-chip} **Supply Chain Risk**{.cve-chip} **Malicious VS Code Extension**{.cve-chip}

    A GitHub employee installed a malicious VS Code extension that compromised their endpoint, allowing threat actor TeamPCP to steal authentication tokens and exfiltrate ~3,800–4,000 internal repositories. Stolen data includes source code, CI/CD workflows, and infrastructure configurations; no customer repository impact confirmed.

    [Read more](2026/Week20/GitHub.md)

-   ![PinTheft](2026/Week20/images/PinTheft.png)

    **PinTheft Linux Privilege Escalation Vulnerability - CVE-2026-31635**

    **CVE-2026-31635**{.cve-chip} **Linux Kernel LPE**{.cve-chip} **RDS Subsystem**{.cve-chip} **Public Exploit**{.cve-chip}

    A double-free in the Linux kernel RDS zerocopy send path (`rds_message_zcopy_from_user()`) allows a local unprivileged user to achieve page-cache overwrites via `io_uring` fixed buffer abuse and escalate to root. Public PoC code is available, significantly lowering the bar for exploitation.

    [Read more](2026/Week20/PinTheft.md)

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
