---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
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

-   ![Trust Wallet Hack](Week53/images/wallet.png)
    :material-wallet:{ .lg .middle } **Trust Wallet Chrome Extension Supply-Chain Attack**

    **Supply Chain Attack**{.cve-chip}  
    **Browser Extension**{.cve-chip}  
    **$7M Stolen**{.cve-chip}  
    **Cryptocurrency Theft**{.cve-chip}  
    ---------------------------------

    **Trust Wallet Chrome extension v2.68** compromised via **malicious update** distributed through **Chrome Web Store**. Injected JavaScript executed when users unlocked wallets, exfiltrating **seed phrases and private keys** to attacker servers disguised as analytics traffic. Attackers used stolen credentials to sign **legitimate blockchain transactions** draining funds. **~$7 million stolen** from **hundreds of wallets** across multiple blockchains. Core mobile app and backend **not compromised**. Patched v2.69 released. **Remove v2.68**, update to v2.69+, **migrate to new wallets with fresh seed phrases**, use **hardware wallets** for significant holdings, never enter seeds on recovery websites, and monitor blockchain transactions. Irreversible cryptocurrency loss.

    [:octicons-arrow-right-24: View Full Details](Week53/wallet.md)

-   ![LangChain Vulnerability](Week53/images/langchain.png)
    :material-robot-confused-outline:{ .lg .middle } **CVE-2025-68664 LangChain Serialization Injection**

    **Serialization Injection**{.cve-chip}  
    **Secret Exposure**{.cve-chip}  
    **Code Execution**{.cve-chip}  
    **AI Framework**{.cve-chip}  
    ---------------------------------

    **CVE-2025-68664** critical flaw in **LangChain Core** serialization functions (`dumps()`/`dumpd()`) fails to escape dictionaries with **"lc" marker key**. User-controlled data flows into serialization/deserialization cycles (caching, logging, event streaming), treated as **trusted LangChain objects**. Enables **unsafe object instantiation**, **environment secret exposure** (API keys, credentials), and **Jinja2 SSTI code execution**. Affects **langchain-core ≥1.0.0 <1.2.5** and **0.x <0.3.81**. Patched in **1.2.5/0.3.81**. CWE-502. **Update immediately**, apply object allowlists, disable `secrets_from_env`, block Jinja2, sanitize user inputs, minimize serialization scope, use secret managers, and isolate AI workflows.

    [:octicons-arrow-right-24: View Full Details](Week53/langchain.md)

</div>
