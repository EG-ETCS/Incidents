---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![Samsung](2026/Week25/images/Samsung.png)

    **Samsung KNOX Kernel UAF Exposes Millions of Galaxy Devices**

    **Kernel UAF**{.cve-chip} **Android Privilege Escalation**{.cve-chip} **Mobile Security**{.cve-chip} **KNOX Stack**{.cve-chip}

    CVE-2026-20971 is a use-after-free race condition in Samsung’s KNOX PROCA/FIVE subsystems that allows an untrusted app to corrupt kernel memory, potentially enabling full device takeover on Galaxy S9–S25 and A-series devices despite KNOX protections.The flaw remained in production for roughly eight years before being patched in the January 2026 Android Security Maintenance Release, leaving hundreds of millions of devices globally exposed until they receive firmware with security patch level 2026-01-01 or later.

    [Read more](2026/Week25/Samsung.md)

-   ![FortiBleed](2026/Week25/images/Fortibleed.png)

    **FortiBleed Campaign Turns FortiGate Firewalls into Credential Stealers**

    **Credential Harvesting**{.cve-chip} **Initial Access**{.cve-chip} **Edge Device Compromise**{.cve-chip} **Password Cracking**{.cve-chip} **VPN Abuse**{.cve-chip}

    FortiBleed is a Russian-speaking initial-access broker campaign that brute-forces and compromises Fortinet FortiGate firewalls, deploying a Golang sniffer to harvest over 110 million credentials from more than 430,000 targets and converting edge firewalls into large-scale credential sensors.Harvested admin and VPN credentials for roughly 73,000–87,000 FortiGate devices across 194 countries are cracked on a 45‑GPU cluster and reused for VPN, AD/LDAP, RDWeb, Citrix, and database access, enabling deep lateral movement and data theft in government, telecom, finance, healthcare, and other critical sectors.
    [Read more](2026/Week25/Fortibleed.md)

-   ![WhatsApp](2026/Week25/images/WhatsApp.png)

    **WhatsApp Business Document Phishing & RMM Malware Campaign**

    **Phishing**{.cve-chip} **Social Engineering**{.cve-chip} **RMM Abuse**{.cve-chip} **LOLBins**{.cve-chip} **Credential Theft**{.cve-chip}

    Threat actors send fake invoices and purchase orders via WhatsApp to trick victims into executing malware that silently installs legitimate RMM tools (AnyDesk, ScreenConnect), granting persistent remote access for credential theft, lateral movement, and ransomware deployment.

    Telemetry data from cybersecurity company Kaspersky shows that the campaign spreads across Brazil, India, Mexico, Singapore, the UK, Spain, Taiwan, Australia, Russia, Vietnam, and Malaysia.

    [Read more](2026/Week25/WhatsApp.md)

-   ![Apple](2026/Week25/images/Apple.png)

    **Usbliter8 Apple BootROM Exploit**

    **BootROM Exploit**{.cve-chip} **Unpatchable**{.cve-chip} **A12/A13 Chips**{.cve-chip} **Physical Access**{.cve-chip} **Chain-of-Trust Bypass**{.cve-chip}

    A newly disclosed exploit bypasses Apple boot defenses on A12/A13 devices via crafted USB packets, enabling arbitrary code execution before iOS security protections initialize. Because the BootROM is hardware-embedded, the vulnerability cannot be fully patched — device replacement is the only complete mitigation.

    [Read more](2026/Week25/Apple.md)

-   ![Cisco](2026/Week25/images/Cisco.png)

    **Cisco ISE Critical Command Execution Vulnerability – CVE-2026-20181**

    **CVE-2026-20181**{.cve-chip} **Remote Code Execution**{.cve-chip} **Privilege Escalation**{.cve-chip} **Cisco ISE**{.cve-chip} **Network Access Control**{.cve-chip}

    A critical (CVSS 9.1) flaw in Cisco ISE and ISE-PIC allows an authenticated admin to execute OS commands via crafted HTTP requests and escalate to root, risking full NAC infrastructure compromise, policy manipulation, and credential theft across integrated identity systems.

    [Read more](2026/Week25/Cisco.md)

-   ![AryStinger](2026/Week25/images/AryStinger.png)

    **AryStinger Botnet Infects Thousands of D-Link Routers Worldwide**

    **CVE-2013-3307**{.cve-chip} **CVE-2016-5681**{.cve-chip} **CVE-2025-11837**{.cve-chip} **IoT Botnet**{.cve-chip} **End-of-Life Devices**{.cve-chip} **DNS Hijacking**{.cve-chip}

    A previously undocumented botnet has hijacked 4,000+ end-of-life D-Link routers worldwide using old HNAP/RCE CVEs, turning them into proxy, scanning, and DNS-hijacking executors. A Go-based variant also targets NAS devices. Geographic focus is South Korea and China.

    [Read more](2026/Week25/AryStinger.md)

</div>
