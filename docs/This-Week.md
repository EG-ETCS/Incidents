---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![forticlientems](2026/Week6/images/forticlientems.png)

    **Fortinet FortiClientEMS Critical SQL Injection (CVE-2026-21643)**

    **CVE-2026-21643**{.cve-chip} **SQL Injection**{.cve-chip} **Unauthenticated**{.cve-chip} **Remote Code Execution**{.cve-chip} **Fortinet**{.cve-chip}

    A critical SQL injection in FortiClientEMS 7.4.4 allows unauthenticated attackers to send crafted HTTP requests to the admin interface and execute arbitrary SQL. The flaw can lead to remote code execution and compromise of the EMS management server.

    Because FortiClientEMS centrally manages endpoints, a successful compromise can cascade into wider enterprise risk. Upgrading to 7.4.5 or later and restricting admin interface exposure are key mitigations.

    [:octicons-arrow-right-24: Read more](2026/Week6/forticlientems.md)

-   ![unc3886](2026/Week6/images/unc3886.png)

    **UNC3886 Cyber Espionage Campaign Against Singapore Telcos**

    **Cyber Espionage**{.cve-chip} **Telecommunications**{.cve-chip} **Zero-Day Exploitation**{.cve-chip} **Rootkits**{.cve-chip} **National Security**{.cve-chip}

    Singapore’s CSA and IMDA reported a prolonged UNC3886 espionage campaign targeting telecom networks. Attackers exploited a firewall zero-day, deployed rootkits for stealth persistence, and exfiltrated limited technical network data without disrupting core services.

    While no customer data was exposed and core 5G infrastructure remained segmented, the incident prompted a major national cyber response due to the strategic risk posed to critical infrastructure.

    [:octicons-arrow-right-24: Read more](2026/Week6/unc3886.md)

-   ![smartermail](2026/Week6/images/smartermail.png)

    **SmarterMail Unauthenticated Remote Code Execution (RCE)**

    **CVE-2026-24423**{.cve-chip} **Unauthenticated RCE**{.cve-chip} **Email Server**{.cve-chip} **CVSS 9.3**{.cve-chip} **Active Exploitation**{.cve-chip}

    A critical flaw in SmarterMail’s ConnectToHub API allows unauthenticated attackers to submit crafted requests that cause the server to fetch attacker-controlled JSON and execute OS commands. The issue affects all builds prior to 100.0.9511 and has been linked to ransomware activity.

    Successful exploitation enables full server compromise, data theft from email systems, and lateral movement across networks. Patching to Build 9511 or later is required to mitigate the vulnerability.

    [:octicons-arrow-right-24: Read more](2026/Week6/smartermail.md)

-   ![dknife](2026/Week6/images/dknife.png)

    **DKnife – Linux-based Adversary-in-the-Middle (AiTM) Traffic-Hijacking Toolkit**

    **Adversary-in-the-Middle**{.cve-chip} **Traffic Hijacking**{.cve-chip} **Router Malware**{.cve-chip} **DNS Manipulation**{.cve-chip} **Credential Theft**{.cve-chip}

    DKnife is a modular post-compromise toolkit that runs on Linux-based routers and edge devices, intercepting and manipulating network traffic to spy on users, harvest credentials, and hijack downloads and updates for malware delivery.

    The framework deploys components for DPI, TLS interception, DNS hijacking, and P2P VPN C2. It can swap update manifests, inject payloads like ShadowPad, and maintain persistence via an updater/watchdog on compromised gateways.

    [:octicons-arrow-right-24: Read more](2026/Week6/dknife.md)

-   ![bridgepay](2026/Week6/images/bridgepay.png)

    **BridgePay Network Solutions Ransomware Attack**

    **Ransomware**{.cve-chip} **Payment Systems Outage**{.cve-chip} **Critical Infrastructure**{.cve-chip} **Service Disruption**{.cve-chip} **Forensic Response**{.cve-chip}

    BridgePay confirmed a ransomware attack that knocked key payment services offline, causing nationwide outages of payment APIs, virtual terminals, and hosted payment pages. Early forensic findings show file encryption but no evidence of payment card data compromise.

    Federal law enforcement and external cybersecurity teams are engaged in investigation and recovery. Merchants and municipal billing portals reported outages, with ongoing service degradation and no clear ETA for full restoration.

    [:octicons-arrow-right-24: Read more](2026/Week6/bridgepay.md)

-   ![signal](2026/Week6/images/signal.png)

    **Signal Account Hijacking Campaign**

    **Phishing**{.cve-chip} **Account Takeover**{.cve-chip} **Social Engineering**{.cve-chip} **QR Code**{.cve-chip} **Registration Lock**{.cve-chip}

    German security agencies warned of phishing attacks on Signal that trick victims into handing over PINs or scanning QR codes, allowing attackers to hijack accounts or link their devices. The campaign relies on social engineering rather than malware or software vulnerabilities.

    Once linked, attackers can read chats, access contact lists, impersonate victims, and target group networks. High-risk targets include politicians, military personnel, and journalists.

    [:octicons-arrow-right-24: Read more](2026/Week6/signal.md)

</div>
