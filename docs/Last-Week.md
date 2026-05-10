---
hide:
  - navigation
  - toc
---

# Last Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![Taiwan](2026/Week18/images/Taiwan.png)

    **Student Hacked Taiwan High-Speed Rail to Trigger Emergency Brakes**

    **OT Security**{.cve-chip} **TETRA Radio Spoofing**{.cve-chip} **Rail Infrastructure**{.cve-chip}

    A student used SDR equipment and cloned radios to inject a forged "General Alarm" onto Taiwan High Speed Rail's TETRA network, halting four trains for 48 minutes. The attack required no software exploit — static TETRA parameters unchanged for 19 years allowed a decoded beacon clone to bypass all seven verification layers.

    [Read more](2026/Week18/Taiwan.md)

-   ![Edge](2026/Week18/images/Edge.png)

    **Microsoft Edge Stores Passwords in Process Memory, Posing Enterprise Risk**

    **Microsoft Edge**{.cve-chip} **Credential Exposure**{.cve-chip} **Enterprise Risk**{.cve-chip}

    Microsoft Edge decrypts all saved passwords into process memory at browser startup and keeps them resident in cleartext. Any attacker who reaches admin/SYSTEM on the endpoint can dump Edge memory and recover every stored credential — Microsoft confirmed this is "by design" with no CVE or fix planned.

    [Read more](2026/Week18/Edge.md)

-   ![Facebook](2026/Week18/images/Facebook.png)

    **30,000 Facebook Accounts Hacked via Google AppSheet Phishing Campaign**

    **Facebook Phishing**{.cve-chip} **Google AppSheet Abuse**{.cve-chip} **Account Takeover**{.cve-chip} **Credential Theft**{.cve-chip}

    A large phishing operation abused Google AppSheet delivery infrastructure to send trusted-looking lures that redirected victims to fake Facebook login pages.

    Attackers validated stolen credentials in real time, rapidly hijacked accounts, and monetized access through resale and abuse.

    [Read more](2026/Week18/Facebook.md)

-   ![China](2026/Week18/images/China.png)

    **China-Linked Cyber Espionage Campaign Targeting Asian Governments**

    **China-Linked APT**{.cve-chip} **Government Espionage**{.cve-chip} **Exchange Exploitation**{.cve-chip} **Long-Term Persistence**{.cve-chip}

    A China-linked actor reportedly targeted government and defense-related organizations by exploiting unpatched Microsoft Exchange systems and abusing stolen credentials for stealth access.

    The campaign focused on persistent mailbox and network compromise to collect intelligence over long periods with reduced detection.

    [Read more](2026/Week18/China.md)

-   ![Linux](2026/Week18/images/Linux.png)

    **Actively Exploited Linux Privilege Escalation Vulnerability**

    **CVE-2026-31431**{.cve-chip} **Linux Privilege Escalation**{.cve-chip} **CISA KEV**{.cve-chip} **Active Exploitation**{.cve-chip}

    CISA added CVE-2026-31431 to KEV after confirmed exploitation, highlighting a Linux privilege-escalation path that can elevate low-privileged access to root.

    The issue raises post-compromise risk across Linux environments and can enable persistence, data theft, and lateral movement if patching is delayed.


    [Read more](2026/Week18/Linux.md)

-   ![cPanel](2026/Week18/images/cPanel.png)

    **cPanel & WHM Authentication Bypass Vulnerability**

    **CVE-2026-41940**{.cve-chip} **cPanel/WHM**{.cve-chip} **Authentication Bypass**{.cve-chip} **Zero-Day Exploitation**{.cve-chip}

    A critical cPanel/WHM flaw allowed unauthenticated session forgery via request-handling abuse, with exploitation reported before emergency patches were released.

    Successful compromise can expose multi-tenant hosting environments to account takeover, malware deployment, and broader supply-chain style impact.

    [Read more](2026/Week18/cPanel.md)

</div>
