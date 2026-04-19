---
hide:
  - navigation
  - toc
---

# Last Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![Mirax](2026/Week15/images/Mirax.png)

    **Mirax Android Malware Campaign**

    **Android Malware**{.cve-chip} **Banking Trojan**{.cve-chip} **Malware-as-a-Service**{.cve-chip}

    Mirax is a fully-featured Android RAT distributed via malvertising that infected 220,000+ devices. It steals banking credentials through overlay attacks, intercepts OTPs, and silently converts victim devices into SOCKS5 proxy nodes. Operated as a MaaS platform, it primarily targets Spanish-speaking users.

    [Read more](2026/Week15/Mirax.md)

-   ![excel](2026/Week15/images/excel.png)

    **Microsoft Excel Legacy Vulnerability Exploitation (CVE-2009-0238)**

    **CVE-2009-0238**{.cve-chip} **Remote Code Execution**{.cve-chip} **Active Exploitation**{.cve-chip}

    A 15-year-old memory corruption flaw in legacy Microsoft Excel is being actively exploited. Attackers deliver malicious `.xls` files via phishing to trigger arbitrary code execution on unpatched systems, enabling full compromise, data theft, and lateral movement. CISA has added the vulnerability to its Known Exploited Vulnerabilities catalog.

    [Read more](2026/Week15/excel.md)

-   ![WordPress](2026/Week15/images/WordPress.png)

    **WordPress Plugin Supply Chain Attack (EssentialPlugin Compromise)**

    **Supply Chain Attack**{.cve-chip} **WordPress**{.cve-chip} **Backdoor**{.cve-chip}

    An attacker compromised the EssentialPlugin developer to backdoor 30+ WordPress plugins and distribute malicious updates through official channels. Thousands of sites were infected with remote-access backdoors enabling spam injection, malicious redirects, and full admin takeover.

    [Read more](2026/Week15/WordPress.md)

-   ![chrome](2026/Week15/images/chrome.png)

    **Malicious Chrome Extensions Campaign (108 Extensions Data Theft Operation)**

    **Credential Theft**{.cve-chip} **Browser Security**{.cve-chip} **Supply Chain Attack**{.cve-chip}

    108 malicious extensions disguised as Telegram tools, video enhancers, and translators were uploaded to the Chrome Web Store and stole Google OAuth tokens and Telegram session cookies from ~20,000 users. Attackers leveraged the stolen tokens to hijack accounts and bypass MFA entirely, with some extensions also providing backdoor command execution capabilities.

    [Read more](2026/Week15/chrome.md)

-   ![microsoft](2026/Week15/images/microsoft.png)

    **Microsoft Patch Tuesday April 2026 — 165 Vulnerabilities Fixed, SharePoint Zero-Day Exploited**

    **Patch Tuesday**{.cve-chip} **Zero-Day**{.cve-chip} **Remote Code Execution**{.cve-chip}

    Microsoft's April 2026 Patch Tuesday addressed 165 vulnerabilities, including a critical actively-exploited zero-day in on-premises SharePoint Server. Attackers can exploit the flaw remotely to execute code, move laterally, and deploy ransomware — unpatched internet-facing SharePoint servers remain at immediate risk.

    [Read more](2026/Week15/microsoft.md)

-   ![Handala](2026/Week15/images/Handala.png)

    **Iran-Linked Group Handala Claims to Have Breached Three Major UAE Organizations**

    **Iran-Linked Hacktivists**{.cve-chip} **Data Exfiltration Claim**{.cve-chip} **Destructive Attack Claim**{.cve-chip}

    Handala claims it breached Dubai Courts, Dubai Land Department, and Dubai Roads & Transport Authority, allegedly exfiltrating massive amounts of data and carrying out destructive actions. The claims remain unconfirmed, but the incident fits broader regional cyber tension and psychological pressure tactics.

    [Read more](2026/Week15/Handala.md)

-   ![Booking](2026/Week15/images/Booking.png)
    
    **Hackers Access Booking.com User Data, Company Secures Systems**

    **Data Breach**{.cve-chip} **Travel Platform**{.cve-chip} **PII Exposure**{.cve-chip}

    Booking.com confirmed unauthorized access to customer reservation data, exposing names, contact details, booking information, and communications. While payment card data was reportedly not accessed, the stolen travel context creates strong follow-on phishing and fraud risk.

    [Read more](2026/Week15/Booking.md)

-   ![APT37](2026/Week15/images/APT37.png)
  
    **North Korea's APT37 Uses Facebook Social Engineering to Deliver RokRAT Malware**

    **North Korea-Linked APT**{.cve-chip} **Social Engineering**{.cve-chip} **RokRAT Malware**{.cve-chip}

    APT37 used fake Facebook profiles and Messenger conversations to trick targets into installing a trojanized PDF viewer that deployed RokRAT. The malware provided persistent remote access and covert data exfiltration through compromised legitimate websites.

    [Read more](2026/Week15/APT37.md)

-   ![JanelaRAT](2026/Week15/images/JanelaRAT.png)

    **JanelaRAT Malware Targets Latin American Banks with 14,739 Attacks in Brazil in 2025**

    **Banking Malware**{.cve-chip} **Remote Access Trojan**{.cve-chip} **Latin America**{.cve-chip}

    JanelaRAT is a banking-focused RAT delivered through phishing and a staged DLL side-loading chain. It installs a malicious Chromium extension, monitors banking sessions through window titles, and steals credentials or active session data for financial fraud.

    [Read more](2026/Week15/JanelaRAT.md)

-   ![Webloc](2026/Week15/images/Webloc.png)

    **Citizen Lab: Webloc Tracked 500M Devices for Global Law Enforcement**

    **Ad-Tech Surveillance**{.cve-chip} **Location Tracking**{.cve-chip} **Privacy Risk**{.cve-chip}

    Citizen Lab reported that Webloc enabled global device tracking by leveraging commercial ad-tech telemetry such as MAIDs, RTB bidstream data, and brokered location records. The model reconstructs movement histories and geofence presence without malware or direct device hacking.

    [Read more](2026/Week15/Webloc.md)

-   ![ShowDoc](2026/Week15/images/ShowDoc.png)

    **ShowDoc RCE Flaw CVE-2025-0520 Actively Exploited on Unpatched Servers**

    **Remote Code Execution**{.cve-chip} **Web Application Security**{.cve-chip} **Active Exploitation**{.cve-chip}

    Attackers are exploiting improper file upload validation in vulnerable ShowDoc versions to upload web shells and achieve remote code execution. Unpatched internet-exposed instances can be fully compromised and used for data theft, malware deployment, and lateral movement.

    [Read more](2026/Week15/ShowDoc.md)

-   ![France](2026/Week15/images/France.png)

    **France Government Migration from Windows to Linux (Digital Sovereignty Initiative)**

    **Digital Sovereignty**{.cve-chip} **Linux Migration**{.cve-chip} **Public Sector Security**{.cve-chip} **Vendor Independence**{.cve-chip}

    France announced a phased public-sector shift from Windows toward Linux-based systems to reduce foreign technology dependence and increase control over sensitive infrastructure.

    The initiative prioritizes auditability, patch-governance autonomy, and long-term resilience, while requiring careful risk management during hybrid migration phases.

    [Read more](2026/Week15/France.md)

-   ![SCADA](2026/Week15/images/SCADA.png)

    **Exposed ICS/SCADA Devices Targeted by Iranian APTs (Censys Report)**

    **ICS/SCADA Exposure**{.cve-chip} **Iranian APT Activity**{.cve-chip} **Rockwell/Allen-Bradley**{.cve-chip} **Critical Infrastructure Risk**{.cve-chip}

    Censys reported thousands of internet-exposed industrial control devices, including Rockwell/Allen-Bradley PLC-related systems, with threat activity linked to Iranian-affiliated actors.

    Exposed EtherNet/IP and weak remote services increase the risk of unauthorized PLC logic manipulation, operational disruption, and potential physical-impact incidents.

    [Read more](2026/Week15/SCADA.md)

-   ![Android](2026/Week15/images/Android.png)

    **EngageLab SDK Flaw Opens Door to Private Data on 50M Android Devices**

    **Android SDK Risk**{.cve-chip} **Intent Redirection**{.cve-chip} **EngageLab SDK**{.cve-chip} **Mobile Data Exposure**{.cve-chip}

    A vulnerability in EngageLab's Android SDK reportedly let malicious apps abuse unsafe intent handling to access private data from other installed apps.

    The flaw affected exported component behavior in vulnerable integrations, creating credential, token, and wallet-data exposure risk at large installation scale.

    [Read more](2026/Week15/Android.md)

-   ![Adobe](2026/Week15/images/Adobe.png)

    **Adobe Acrobat Reader Zero-Day (CVE-2026-34621)**

    **CVE-2026-34621**{.cve-chip} **Adobe Acrobat Reader**{.cve-chip} **Prototype Pollution**{.cve-chip} **Active Exploitation**{.cve-chip}

    Adobe patched an actively exploited zero-day in Acrobat Reader where malicious PDFs with embedded JavaScript could trigger code execution through prototype-pollution abuse.

    The campaign reportedly ran for months before patch release and may be chained with additional techniques for persistence, credential theft, and broader endpoint compromise.

    [Read more](2026/Week15/Adobe.md)

</div>
