---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![Lotusbail npm Attack](Week52/images/lotusbail.png)
    :material-package-variant-closed:{ .lg .middle } **Lotusbail Malicious npm Package**

    **Supply Chain Attack**{.cve-chip}  
    **npm Package**{.cve-chip}  
    **WhatsApp Compromise**{.cve-chip}  
    **56,000+ Downloads**{.cve-chip}  
    ---------------------------------

    **Lotusbail** malicious npm package disguised as WhatsApp Web API library downloaded **56,000+ times**. Trojanized fork of **@whiskeysockets/baileys** appeared functional while secretly intercepting WhatsApp traffic. **Malicious WebSocket wrapper** captured **credentials, messages, contacts, media, and session tokens**. Used **hardcoded pairing code** to silently link **attacker's device** to victim's WhatsApp account, creating **persistent access** surviving package removal. Data exfiltrated via custom encryption to attacker servers. **Remove package**, **unlink unknown devices** in WhatsApp settings, rotate credentials, vet packages before installation, use **npm audit** and scanning tools (Snyk, Socket.dev), monitor runtime behavior, and enable WhatsApp two-step verification. Supply chain attack targeting developers.

    [:octicons-arrow-right-24: View Full Details](Week52/lotusbail.md)

-   ![MacSync Malware](Week52/images/macsync.png)
    :material-apple:{ .lg .middle } **MacSync macOS Stealer: Code-Signed Gatekeeper Bypass**

    **macOS Malware**{.cve-chip}  
    **Code-Signed**{.cve-chip}  
    **Gatekeeper Bypass**{.cve-chip}  
    **Credential Theft**{.cve-chip}  
    ---------------------------------

    **MacSync** macOS stealer distributed via **digitally signed and Apple-notarized** fake installers (e.g., "zk-call-messenger-installer-3.9.2-lts.dmg"). **Valid Apple Developer ID signature** and notarization bypass **Gatekeeper and XProtect** without warnings. Swift dropper performs environment checks, downloads encoded payload from remote server. **Go-based stealer** (derived from Mac.c) harvests **Keychain passwords**, **browser credentials**, **cryptocurrency wallets**, **SSH keys**, and **cloud tokens**. Establishes **LaunchAgent persistence** and C2 connection. .dmg padded to ~25.5 MB with decoy PDFs. Certificate later revoked. Download from **App Store or official sites only**, verify developer signatures, keep macOS updated, deploy EDR with behavioral monitoring, enable Application Firewall, and monitor LaunchAgents/network connections.

    [:octicons-arrow-right-24: View Full Details](Week52/macsync.md)

-   ![FBI Domain Seizure](Week52/images/fbi.png)
    :material-bank-remove:{ .lg .middle } **FBI Seizure: $14.6M Bank Fraud Domain**

    **Bank Fraud**{.cve-chip}  
    **Phishing Campaign**{.cve-chip}  
    **$14.6M Losses**{.cve-chip}  
    **Domain Seizure**{.cve-chip}  
    ---------------------------------

    **FBI seized web3adspanels.org** used to store stolen **online banking credentials** from U.S. victims. Attackers purchased **malicious Google/Bing ads** targeting banking keywords, redirecting to **fake bank websites** mimicking legitimate portals. Victims entered credentials on phishing sites; **JavaScript capture scripts** transmitted data to centralized backend on seized domain. Attackers used credentials for **account takeovers** and **fraudulent wire transfers**. **$14.6M confirmed losses**, **$28M attempted fraud**. Avoid clicking search ads, **bookmark banking URLs**, manually type domains, enable **phishing-resistant MFA**, use password managers, monitor accounts with real-time alerts, and report phishing infrastructure to FBI/IC3.

    [:octicons-arrow-right-24: View Full Details](Week52/fbi.md)

</div>
