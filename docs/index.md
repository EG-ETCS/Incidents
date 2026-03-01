---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![dohdoor](2026/Week9/images/dohdoor.png)

    **UAT-10027 Targets U.S. Education and Healthcare with Dohdoor Backdoor**

    **Dohdoor Backdoor**{.cve-chip} **UAT-10027**{.cve-chip} **DoH C2**{.cve-chip} **Healthcare/Education**{.cve-chip}

    An ongoing campaign active since at least December 2025 is targeting U.S. education and healthcare organizations with the previously undocumented Dohdoor backdoor. The infection chain uses phishing-linked PowerShell, staged loaders, DLL sideloading via trusted Windows binaries, and encrypted DNS-over-HTTPS C2 traffic over port 443.

    Post-compromise activity includes in-memory payload execution consistent with Cobalt Strike behavior and evasion techniques that reduce endpoint/network visibility, increasing the risk of persistence, lateral movement, and credential theft.

    [:octicons-arrow-right-24: Read more](2026/Week9/dohdoor.md)

-   ![Juniper](2026/Week9/images/Juniper.png)

    **Juniper Networks PTX Series Router Critical Vulnerability (CVE-2026-21902)**

    **CVE-2026-21902**{.cve-chip} **Remote Code Execution**{.cve-chip} **Unauthenticated**{.cve-chip} **Root Access**{.cve-chip}

    A critical flaw in Junos OS Evolved on PTX Series routers can allow remote unauthenticated attackers to execute code as root due to improper permission assignment in the On-Box Anomaly Detection framework. The vulnerable service is exposed externally by mistake and enabled by default in affected builds.

    Successful exploitation can result in full router takeover, traffic manipulation, and severe operational risk for ISP, telecom, and enterprise backbone environments that depend on PTX routing infrastructure.

    [:octicons-arrow-right-24: Read more](2026/Week9/Juniper.md)

-   ![apex](2026/Week9/images/apex.png)

    **Trend Micro Apex One Critical RCE Vulnerabilities**

    **CVE-2025-71210**{.cve-chip} **CVE-2025-71211**{.cve-chip} **Path Traversal**{.cve-chip} **Apex One**{.cve-chip}

    Trend Micro patched critical Apex One vulnerabilities that can lead to remote code execution on on-premises management servers through path traversal and improper input validation. Attackers may write malicious files to unintended directories and execute them with high privileges.

    Compromise of a security management platform creates a high-trust pivot point, enabling potential malicious policy pushes, protection bypass, lateral movement, and broad ransomware or data-theft impact across managed endpoints.

    [:octicons-arrow-right-24: Read more](2026/Week9/apex.md)

</div>