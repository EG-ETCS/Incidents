---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![ipcameras](2026/Week9/images/ipcameras.png)

    **Iran-linked Cyber Espionage Campaign Targeting Internet-Connected Surveillance Cameras**

    **Iran-Linked Activity**{.cve-chip} **IP Camera Targeting**{.cve-chip} **Reconnaissance Operations**{.cve-chip} **IoT Exposure**{.cve-chip}

    Researchers reported a surge in intrusion attempts linked to Iranian threat infrastructure targeting internet-connected surveillance cameras in several Middle Eastern countries. The campaign appears focused on accessing live and recorded video streams for reconnaissance near public, infrastructure, and potentially sensitive sites.

    Attackers are believed to combine internet exposure, weak/default credentials, and known firmware weaknesses in commonly deployed camera ecosystems to obtain administrative access and monitor real-time developments during regional conflict.

    [:octicons-arrow-right-24: Read more](2026/Week9/ipcameras.md)

-   ![DDos](2026/Week9/images/DDos.png)

    **Hacktivist DDoS Campaign Targeting 110 Organizations Across 16 Countries After Middle East Conflict**

    **Hacktivist Campaign**{.cve-chip} **DDoS Operations**{.cve-chip} **Geopolitical Trigger**{.cve-chip} **Multi-Country Impact**{.cve-chip}

    A coordinated wave of 149 claimed DDoS attacks reportedly hit 110 organizations across 16 countries, with government portals and public-facing infrastructure among the most targeted sectors. The campaign involved at least 12 hacktivist groups and appears closely tied to geopolitical escalation in the Middle East.

    Reported tactics include Layer-7 HTTP floods, TCP SYN floods, UDP amplification, and botnet-driven traffic surges designed to disrupt service availability and amplify political messaging through public claim channels.

    [:octicons-arrow-right-24: Read more](2026/Week9/DDos.md)

-   ![mail2shell](2026/Week9/images/mail2shell.png)

    **Mail2Shell zero-click attack lets hackers hijack FreeScout mail servers**

    **CVE-2026-28289**{.cve-chip} **Mail2Shell**{.cve-chip} **Zero-Click RCE**{.cve-chip} **Unicode Bypass**{.cve-chip}

    Researchers disclosed a critical FreeScout vulnerability where a crafted email attachment can bypass filename protections using hidden Unicode characters and write dangerous files such as `.htaccess`. The flaw can be exploited without user interaction when inbound mail is automatically processed.

    Successful abuse may enable unauthenticated remote code execution, web shell deployment, and full helpdesk server compromise—putting support tickets, customer communications, and attached data at risk.

    [:octicons-arrow-right-24: Read more](2026/Week9/mail2shell.md)

-   ![coruna](2026/Week9/images/coruna.png)

    **Coruna iOS Exploit Kit (aka CryptoWaters)**

    **Coruna/CryptoWaters**{.cve-chip} **iOS Exploit Kit**{.cve-chip} **WebKit Chains**{.cve-chip} **Mobile Surveillance-to-Crime**{.cve-chip}

    Researchers uncovered the Coruna exploit framework targeting iOS 13 through 17.2.1, with 23 exploits organized into five complete chains delivered via malicious or compromised websites. Hidden JavaScript loaders fingerprint device model and iOS version, then trigger chain-specific exploitation.

    Reported post-exploitation includes PlasmaLoader payload delivery, DGA-based C2 fallback, and theft of wallet/app data, illustrating how advanced mobile exploitation tooling can spread from surveillance operations into broader criminal ecosystems.

    [:octicons-arrow-right-24: Read more](2026/Week9/coruna.md)

-   ![azureAD](2026/Week9/images/azureAD.png)

    **CVE-2026-2628 – Microsoft 365 / Azure AD SSO Authentication Bypass in WordPress Plugin**

    **CVE-2026-2628**{.cve-chip} **Authentication Bypass**{.cve-chip} **WordPress Plugin**{.cve-chip} **Azure AD SSO**{.cve-chip}

    A critical flaw in the All-in-One Microsoft 365 & Entra ID / Azure AD SSO Login plugin (<= 2.2.5) can allow remote attackers to bypass authentication and log in as arbitrary WordPress users, including administrators, without valid credentials.

    Exploitation may lead to full site takeover, malicious plugin/theme deployment, sensitive data exposure, and potential lateral movement where WordPress infrastructure is poorly segmented from internal systems.

    [:octicons-arrow-right-24: Read more](2026/Week9/azureAD.md)

</div>