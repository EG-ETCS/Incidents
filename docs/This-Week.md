---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![russian](2026/Week7/images/russian.png)

    **Russian Government Attempts to Block WhatsApp and Restrict Telegram**

    **Government Censorship**{.cve-chip} **Network Blocking**{.cve-chip} **DNS Manipulation**{.cve-chip} **WhatsApp**{.cve-chip} **Telegram**{.cve-chip}

    Roskomnadzor, Russia's telecommunications regulator, escalated measures to block WhatsApp nationwide and impose restrictions on Telegram. Authorities removed WhatsApp domains from Russia's national DNS and deployed deep packet inspection (DPI) technology, effectively cutting off access for approximately 100 million users unless they employ DNS workarounds or VPNs.

    The government justifies the blockade as enforcing local laws and combating crime, while critics view it as censorship aimed at promoting MAX, a state-backed alternative messaging app. This represents a significant disruption to personal, business, and emergency communications across Russia.

    [:octicons-arrow-right-24: Read more](2026/Week7/russian.md)

-   ![beyondtrust](2026/Week7/images/beyondtrust.png)

    **CVE-2026-1731 – BeyondTrust Pre-Authentication RCE Vulnerability**

    **CVE-2026-1731**{.cve-chip} **Remote Code Execution**{.cve-chip} **Pre-Authentication**{.cve-chip} **Command Injection**{.cve-chip} **Critical**{.cve-chip}

    A critical command injection vulnerability in BeyondTrust Remote Support and Privileged Remote Access allows unauthenticated attackers to execute arbitrary system commands via specially crafted requests. Attackers began exploiting exposed systems within 24 hours of the public proof-of-concept (PoC) release, compromising service accounts and enabling full system compromise.

    The vulnerability stems from improper input sanitization where unsanitized user input is passed directly to system-level command execution. Affected systems can be completely compromised, leading to credential theft, lateral movement, and potential ransomware deployment across enterprise networks.

    [:octicons-arrow-right-24: Read more](2026/Week7/beyondtrust.md)

-   ![google](2026/Week7/images/google.png)

    **Google Links China, Iran, Russia, North Korea to Coordinated Defense Sector Cyber Operations**

    **State-Sponsored**{.cve-chip} **Defense Sector**{.cve-chip} **Multi-Nation Coordination**{.cve-chip} **Supply Chain Attack**{.cve-chip} **APT**{.cve-chip}

    Google's Threat Intelligence Group discovered persistent, multi-vector cyber operations by state-linked threat clusters from China, Iran, Russia, and North Korea targeting defense sector systems, personnel, and supply chains. These coordinated campaigns employ sophisticated social engineering, recruitment lures, custom malware families (VERMONSTER, MESSYFORK, GREYBATTLE, STALECOOKIE), and obfuscation techniques.

    The operations focus on modern warfare systems including drones, autonomous vehicles, and battlefield communications. Attack vectors include fake recruitment portals, spoofed applications, phishing emails, and edge device exploitation, with attackers using ORB networks for traffic obfuscation and maintaining long-term persistent access.

    [:octicons-arrow-right-24: Read more](2026/Week7/google.md)

</div>
