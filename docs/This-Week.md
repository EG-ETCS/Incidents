---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![beatbanker](2026/Week10/images/beatbanker.png)

    **BeatBanker Android Malware Campaign (Fake Starlink App)**

    **BeatBanker**{.cve-chip} **Android Banking Trojan**{.cve-chip} **Fake App Distribution**{.cve-chip} **Crypto Miner**{.cve-chip}

    Researchers identified a malicious Android campaign distributing BeatBanker through fake Play Store-style websites and Starlink-themed APK lures. The malware abuses high-risk permissions and downloads modular payloads for credential theft, remote access, and crypto-mining.

    Reported behavior includes overlay attacks on banking/crypto apps, C2-driven module loading, and stealth persistence using near-inaudible looping audio to keep a foreground service active on infected devices.

    [:octicons-arrow-right-24: Read more](2026/Week10/beatbanker.md)

-   ![asus](2026/Week10/images/asus.png)

    **KadNap Botnet targeting ASUS Routers**

    **KadNap Botnet**{.cve-chip} **ASUS Routers**{.cve-chip} **Proxy Abuse**{.cve-chip} **P2P C2**{.cve-chip}

    Researchers identified KadNap malware compromising ASUS routers and edge devices, enrolling them into a botnet used as anonymizing proxy infrastructure for cybercrime activity. The campaign uses script-based installation and recurring cron execution to maintain persistence on infected systems.

    By leveraging modified Kademlia-style P2P coordination, attackers reduce centralized command dependency and make takedown more difficult while routing malicious traffic through compromised residential and SMB network gateways.

    [:octicons-arrow-right-24: Read more](2026/Week10/asus.md)

-   ![MR_GM](2026/Week10/images/MR_GM.png)

    **CVE-2026-24448 – Hard-coded Credentials in Industrial Network Devices**

    **CVE-2026-24448**{.cve-chip} **Hard-coded Credentials**{.cve-chip} **CWE-798**{.cve-chip} **OT Network Risk**{.cve-chip}

    A critical vulnerability in MR-GM5L-S1 and MR-GM5A-L1 industrial networking devices allows attackers to use embedded firmware credentials to authenticate without prior privileges and gain administrative access to management interfaces.

    Successful exploitation can expose sensitive operational configuration, enable unauthorized device changes, and increase risk of lateral movement and disruption within segmented or weakly protected OT environments.

    [:octicons-arrow-right-24: Read more](2026/Week10/MR_GM.md)

-   ![cloud](2026/Week10/images/cloud.png)

    **Middle East Cloud Infrastructure Attack / AWS Data Center Drone Strikes**

    **Cloud Infrastructure Risk**{.cve-chip} **Physical Disruption**{.cve-chip} **Regional Outage**{.cve-chip} **Geopolitical Escalation**{.cve-chip}

    Reported drone-strike impacts on Gulf-region cloud facilities highlighted how physical conflict can disrupt digital infrastructure through building damage, utility instability, and regional connectivity stress, even when servers are not directly destroyed.

    The incident underscores resilience gaps for organizations concentrated in a single cloud region and reinforces the need for multi-region failover, independent backups, and tested business continuity plans for multi-domain disruptions.

    [:octicons-arrow-right-24: Read more](2026/Week10/cloud.md)

-   ![russia](2026/Week10/images/russia.png)

    **Russia-linked Hackers Target Signal and WhatsApp Accounts of Officials Globally**

    **Russia-Linked Activity**{.cve-chip} **Account Hijacking**{.cve-chip} **Signal/WhatsApp**{.cve-chip} **Social Engineering**{.cve-chip}

    Dutch intelligence agencies warned of a global Russia-linked campaign targeting officials, military personnel, diplomats, and journalists by stealing verification codes and abusing linked-device workflows in Signal and WhatsApp.

    The operation reportedly does not break end-to-end encryption; it exploits account recovery, device-linking flows, and user trust to hijack or silently monitor high-value communications.

    [:octicons-arrow-right-24: Read more](2026/Week10/russia.md)

-   ![github](2026/Week10/images/github.png)

    **BoryptGrab Infostealer GitHub Distribution Campaign**

    **BoryptGrab**{.cve-chip} **Malicious GitHub Repos**{.cve-chip} **Windows Infostealer**{.cve-chip} **TunnesshClient**{.cve-chip}

    Researchers identified a large-scale malware operation abusing more than 100 fake GitHub repositories disguised as cheats, cracked tools, and utilities to deliver the BoryptGrab infostealer to Windows users. Victims are lured through SEO manipulation and social-engineering download pages.

    The malware steals browser credentials, wallet data, and messaging tokens, and in some cases installs TunnesshClient to establish reverse SSH tunnels and persistent remote access, increasing risk for both individual users and enterprise endpoints.

    [:octicons-arrow-right-24: Read more](2026/Week10/github.md)

-   ![dlink](2026/Week10/images/dlink.png)

    **CVE-2025-70231 – Path Traversal Vulnerability in D-Link DIR-513 Router**

    **CVE-2025-70231**{.cve-chip} **Path Traversal**{.cve-chip} **CWE-22**{.cve-chip} **Unauthenticated Access**{.cve-chip}

    A critical path traversal flaw in D-Link DIR-513 firmware 1.10 allows unauthenticated attackers to abuse unsanitized `FILECODE` handling in `/goform/` endpoints and read sensitive files from the router filesystem.

    Successful exploitation can expose administrator credentials, Wi-Fi and network configuration data, and enable follow-on compromise such as traffic redirection, persistent device takeover, or botnet abuse.

    [:octicons-arrow-right-24: Read more](2026/Week10/dlink.md)

-   ![gps](2026/Week10/images/gps.png)

    **SQL Injection Vulnerability in GPS Tracking System Login – CVE-2018-25192**

    **CVE-2018-25192**{.cve-chip} **SQL Injection**{.cve-chip} **CWE-89**{.cve-chip} **Authentication Bypass**{.cve-chip}

    A high-severity SQL injection vulnerability in GPS Tracking System 2.12 allows unauthenticated attackers to manipulate login queries by injecting payloads into the username parameter, bypassing authentication checks.

    Successful exploitation can expose location and fleet management data, enable unauthorized dashboard access, and provide a foothold for further compromise through record tampering, credential theft, or lateral activity.

    [:octicons-arrow-right-24: Read more](2026/Week10/gps.md)

-   ![tenda](2026/Week10/images/tenda.png)

    **CVE-2026-3804 – Tenda i3 Router Stack-Based Buffer Overflow**

    **CVE-2026-3804**{.cve-chip} **Stack Overflow**{.cve-chip} **CWE-121**{.cve-chip} **Router RCE Risk**{.cve-chip}

    A vulnerability in Tenda i3 firmware 1.0.0.6(2204) affects `/goform/WifiMacFilterSet`, where improper validation of the `index` parameter can trigger a stack-based buffer overflow and destabilize or compromise device operation.

    Attackers with network reachability may exploit the flaw to gain unauthorized control, alter router configuration, redirect traffic, or crash services, creating both security and availability risks at the network edge.

    [:octicons-arrow-right-24: Read more](2026/Week10/tenda.md)

-   ![hikvision](2026/Week10/images/hikvision.png)

    **Hikvision & Rockwell Automation Critical Vulnerabilities Added to KEV Catalog**

    **CVE-2017-7921**{.cve-chip} **CVE-2021-22681**{.cve-chip} **CISA KEV**{.cve-chip} **Critical Infrastructure Risk**{.cve-chip}

    CISA added critical Hikvision and Rockwell Automation vulnerabilities to the KEV catalog, highlighting active exploitation risk across surveillance and industrial environments. The issues enable authentication bypass and credential abuse that can grant attackers elevated operational access.

    Potential outcomes include unauthorized camera/feed access, exposure of sensitive configuration data, and industrial process manipulation through trusted engineering workflows in OT environments.

    [:octicons-arrow-right-24: Read more](2026/Week10/hikvision.md)

-   ![cisco](2026/Week10/images/cisco.png)

    **Critical Vulnerabilities in Cisco Secure Firewall Management Center (FMC)**

    **CVE-2026-20079**{.cve-chip} **CVE-2026-20131**{.cve-chip} **Unauthenticated RCE**{.cve-chip} **Root Access Risk**{.cve-chip}

    Cisco patched two maximum-severity vulnerabilities in Secure Firewall Management Center that can allow remote unauthenticated attackers to execute commands and gain root-level control of the firewall management platform through crafted HTTP requests.

    Because FMC is a centralized policy control plane, successful exploitation can enable security-policy tampering, network-wide security degradation, and potential compromise across connected managed firewall infrastructure.

    [:octicons-arrow-right-24: Read more](2026/Week10/cisco.md)

-   ![USstrategy](2026/Week10/images/USstrategy.png)

    **US Cyber Strategy Targets Adversaries, Critical Infrastructure, and Emerging Technologies**

    **National Cyber Strategy**{.cve-chip} **Critical Infrastructure**{.cve-chip} **Zero Trust**{.cve-chip} **AI & Quantum Security**{.cve-chip}

    The United States released a new national cyber strategy focused on strengthening resilience against nation-state threats, cybercrime, and emerging technology risks. The framework emphasizes coordinated action across government, industry, and international partners to improve prevention, deterrence, and response.

    Priorities include securing critical infrastructure, modernizing federal networks with Zero Trust and AI-driven defense, and accelerating post-quantum readiness to reduce long-term strategic cyber risk.

    [:octicons-arrow-right-24: Read more](2026/Week10/USstrategy.md)

-   ![terndoor](2026/Week10/images/terndoor.png)

    **China-Linked Hackers Use TernDoor, PeerTime, BruteEntry in South American Telecom Attacks**

    **UAT-9244**{.cve-chip} **Telecom Espionage**{.cve-chip} **TernDoor/PeerTime**{.cve-chip} **BruteEntry**{.cve-chip}

    A China-linked threat cluster reportedly targeted South American telecom providers using a custom cross-platform toolkit that includes TernDoor (Windows), PeerTime (Linux), and BruteEntry for credential brute forcing and lateral expansion.

    The campaign demonstrates long-term espionage intent through stealthy persistence, relay-node creation, and sustained command-and-control access across telecom infrastructure supporting sensitive communications flows.

    [:octicons-arrow-right-24: Read more](2026/Week10/terndoor.md)

-   ![dindoor](2026/Week10/images/dindoor.png)

    **Iranian APT Hacked US Airport, Bank, Software Company**

    **Iran-Linked APT**{.cve-chip} **Dindoor Backdoor**{.cve-chip} **Fakeset Malware**{.cve-chip} **Critical Sector Targeting**{.cve-chip}

    Researchers reported Iran-linked intrusion activity targeting aviation, banking, and software supply-chain organizations, with persistent access operations observed across multiple victims. The campaign deployed custom backdoors including Dindoor and Fakeset to sustain long-term espionage footholds.

    Reported tradecraft includes certificate-signed malware, lateral movement, and attempted data exfiltration from high-value environments, highlighting ongoing strategic intelligence collection risk in critical sectors.

    [:octicons-arrow-right-24: Read more](2026/Week10/dindoor.md)

</div>
