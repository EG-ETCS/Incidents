---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![apt28](2026/Week5/images/apt28.png)

    **Russian APT28 Exploit Zero-Day Hours After Microsoft Discloses Office Vulnerability**

    **CVE-2026-21509**{.cve-chip} **APT28 (Fancy Bear)**{.cve-chip} **Zero-Day Exploitation**{.cve-chip} **State-Sponsored**{.cve-chip} **COVENANT**{.cve-chip}

    Russian state-sponsored APT28 began exploiting CVE-2026-21509, a Microsoft Office security feature bypass, within hours of disclosure. The threat actor targets Ukraine and EU organizations using weaponized documents that bypass OLE mitigations through a sophisticated multi-stage attack chain.
    
    The exploit connects via WebDAV to download malicious payloads, establishes persistence through COM hijacking, and deploys the COVENANT framework for command-and-control over legitimate cloud infrastructure. This rapid exploitation demonstrates APT28's advanced capabilities and focus on strategic espionage targets.

    [:octicons-arrow-right-24: Read more](2026/Week5/apt28.md)

-   ![ghostchat](2026/Week5/images/ghostchat.png)

    **GhostChat – Android Spyware Disguised as Chat/Dating Application**

    **Android Spyware**{.cve-chip} **Sideloaded APK**{.cve-chip} **Data Exfiltration**{.cve-chip} **Social Engineering**{.cve-chip} **WhatsApp**{.cve-chip}

    GhostChat is malicious Android spyware masquerading as a dating application, distributed via sideloaded APKs outside official app stores. The malware displays fake female profiles to lure victims while silently collecting contacts, images, PDFs, and Office documents in the background.
    
    The spyware establishes persistence through boot receivers and foreground services, continuously monitoring for new content. Victims are redirected to attacker-controlled WhatsApp numbers for additional social engineering while their sensitive data is exfiltrated via HTTPS to command-and-control servers.

    [:octicons-arrow-right-24: Read more](2026/Week5/ghostchat.md)

-   ![fortinet](2026/Week5/images/fortinet.png)

    **Over 3.28 Million Fortinet Devices Exposed via FortiCloud SSO Authentication Bypass**

    **CVE-2026-24858**{.cve-chip} **Authentication Bypass**{.cve-chip} **Active Exploitation**{.cve-chip} **3.28M Devices**{.cve-chip} **FortiCloud SSO**{.cve-chip}

    A critical authentication bypass flaw in FortiCloud Single Sign-On affects over 3.28 million internet-exposed Fortinet devices. Attackers with valid FortiCloud credentials can bypass authentication and gain full administrative access to other organizations' FortiGate, FortiManager, FortiAnalyzer, FortiProxy, and FortiWeb devices.
    
    Active exploitation has been confirmed, with attackers downloading configuration files containing firewall rules and VPN credentials, creating persistent backdoor accounts, and using compromised security appliances to pivot into internal enterprise networks. The vulnerability poses high risk to critical infrastructure and government environments.

    [:octicons-arrow-right-24: Read more](2026/Week5/fortinet.md)


</div>
