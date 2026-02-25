---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![phishing](2026/Week8/images/phishing.png)

    **Phishing Campaign Targets Freight and Logistics Orgs in the US, Europe**

    **Credential Phishing**{.cve-chip} **Logistics Sector**{.cve-chip} **Financially Motivated**{.cve-chip} **Account Takeover**{.cve-chip}

    A financially motivated cybercriminal group targeted freight and logistics organizations across the US and Europe using spoofed portals and multi-stage cloaking infrastructure. The campaign reportedly harvested over 1,600 credential sets, including usernames, passwords, 2FA codes, and business identifiers used in freight operations.

    Attackers used urgent business pretexts to drive victims through redirection chains into pixel-perfect fake login pages, then monetized access through account takeover, payment rerouting, fuel card abuse, and double-brokering fraud.

    [:octicons-arrow-right-24: Read more](2026/Week8/phishing.md)

-   ![solarwinds](2026/Week8/images/solarwinds.png)

    **SolarWinds Serv-U Critical Root Access Vulnerabilities**

    **CVE-2025-40538**{.cve-chip} **CVE-2025-40539**{.cve-chip} **CVE-2025-40540**{.cve-chip} **CVE-2025-40541**{.cve-chip}

    SolarWinds patched four critical flaws in Serv-U MFT and Secure FTP that can allow attackers with administrative access to execute arbitrary code and gain root/system-level control. The vulnerabilities affect both Windows and Linux deployments and were fixed in version 15.5.4.

    Exploitation can enable rogue admin creation, privilege escalation, sensitive file exfiltration, and lateral movement, with potential outcomes including ransomware deployment and business disruption in enterprise transfer environments.

    [:octicons-arrow-right-24: Read more](2026/Week8/solarwinds.md)

-   ![filezen](2026/Week8/images/filezen.png)

    **Active Exploitation of FileZen OS Command Injection Vulnerability (CVE-2026-25108)**

    **CVE-2026-25108**{.cve-chip} **OS Command Injection**{.cve-chip} **CWE-78**{.cve-chip} **KEV Listed**{.cve-chip}

    A high-severity OS command injection flaw in Soliton FileZen allows authenticated users to execute arbitrary system commands when Antivirus Check Option is enabled. The vulnerability is actively exploited in the wild and is listed in CISA's Known Exploited Vulnerabilities catalog.

    Affected versions include FileZen 4.2.1–4.2.8 and 5.0.0–5.0.10, with remediation available in 5.0.11+. Exploitation can lead to host compromise, data exposure, and potential lateral movement in connected enterprise environments.

    [:octicons-arrow-right-24: Read more](2026/Week8/filezen.md)

</div>
