---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![GhostPairing Attack](Week53/images/ghostpairing.png)

    :material-whatsapp:{ .lg .middle } **GhostPairing: WhatsApp Account Takeover**

    **Social Engineering**{.cve-chip} 
    **WhatsApp**{.cve-chip} 
    **Account Takeover**{.cve-chip} 
    **Device Linking Abuse**{.cve-chip}

    GhostPairing exploits WhatsApp's legitimate device-linking feature through social engineering. Attackers send phishing messages from compromised accounts appearing as trusted contacts, tricking victims into entering pairing codes on fake verification pages. Once linked, attackers gain full access to all chats, media, and real-time messages while victims remain unaware. No malware, SIM swap, or password theft required—purely social manipulation abusing legitimate functionality.

    [:octicons-arrow-right-24: View Full Details](Week53/ghostpairing.md)

-   ![Fortinet FortiOS Vulnerability](Week53/images/vpn2fa.png)

    :material-shield-alert:{ .lg .middle } **Fortinet FortiOS SSL VPN 2FA Bypass**

    **CVE-2020-12812**{.cve-chip} 
    **CVSS 7.7**{.cve-chip} 
    **Authentication Bypass**{.cve-chip} 
    **2FA Bypass**{.cve-chip}

    Active exploitation of five-year-old vulnerability in Fortinet FortiOS SSL VPN. Improper authentication flaw allows attackers to bypass two-factor authentication by altering username casing. FortiOS treats usernames as case-sensitive while LDAP is case-insensitive, creating authentication logic flaw. Attackers submit valid credentials with altered case (e.g., "Admin" vs "admin"), bypassing local 2FA and authenticating via LDAP without 2FA. Affects misconfigured FortiGate devices with local users + LDAP integration.

    [:octicons-arrow-right-24: View Full Details](Week53/vpn2fa.md)

</div>
