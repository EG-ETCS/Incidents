---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![flock](2026/Week5/images/flock.png)

    **Shutdown of Flock Safety ALPR System in Mountain View**

    **Misconfiguration**{.cve-chip} **Access Control Failure**{.cve-chip} **Privacy Breach**{.cve-chip} **Law Enforcement**{.cve-chip} **License Plate Data**{.cve-chip}

    Mountain View police shut down all Flock Safety ALPR cameras after discovering that hundreds of unauthorized law enforcement agencies could search the city's license-plate data. The incident stemmed from misconfiguration and overly permissive default settings that enabled statewide and nationwide lookups despite local policy restrictions.

    The system was configured to allow broad access across state and federal agencies without proper authorization controls. An internal police audit uncovered the vulnerability, leading to immediate suspension of all cameras pending a City Council review scheduled for February 24, 2026.

    [:octicons-arrow-right-24: Read more](2026/Week5/flock.md)

-   ![n8n](2026/Week5/images/n8n.png)

    **CVE-2026-25049 – Critical Remote Code Execution in n8n Workflow Expressions**

    **CVE-2026-25049**{.cve-chip} **Remote Code Execution**{.cve-chip} **Workflow Automation**{.cve-chip} **Expression Injection**{.cve-chip} **Sandbox Escape**{.cve-chip}

    A critical vulnerability in n8n workflow automation platform allows authenticated users with workflow creation rights to execute arbitrary system commands on the host server. Insufficient sanitization of workflow expressions enables attackers to escape the sandbox and run malicious JavaScript that reaches the underlying operating system.

    When combined with public webhooks, the vulnerability can be triggered remotely. Attackers can steal API tokens, database credentials, and OAuth secrets, then pivot to connected systems including cloud services and internal APIs, compromising the entire automation infrastructure.

    [:octicons-arrow-right-24: Read more](2026/Week5/n8n.md)

-   ![magicinfo](2026/Week5/images/magicinfo.png)

    **CVE-2026-25202 – MagicINFO 9 Server Hardcoded Database Credentials Vulnerability**

    **CVE-2026-25202**{.cve-chip} **Hardcoded Credentials**{.cve-chip} **Database Compromise**{.cve-chip} **Digital Signage**{.cve-chip} **Unauthenticated Access**{.cve-chip}

    A critical vulnerability in Samsung MagicINFO 9 Server embeds database credentials directly into the application code. Attackers with network access can discover these hardcoded credentials and log directly into the backend database, bypassing all application-level authentication controls.

    The flaw affects versions prior to 21.1090.1 and enables unauthorized access to sensitive signage content and configurations. Internet-exposed signage infrastructure face high risk of manipulation, data theft, and service disruption.

    [:octicons-arrow-right-24: Read more](2026/Week5/magicinfo.md)

-   ![cisco](2026/Week5/images/cisco.png)

    **Cisco Meeting Management Arbitrary File Upload Vulnerability**

    **CVE-2026-20098**{.cve-chip} **Arbitrary File Upload**{.cve-chip} **Remote Code Execution**{.cve-chip} **Privilege Escalation**{.cve-chip} **Authenticated**{.cve-chip}

    A critical vulnerability in Cisco Meeting Management allows authenticated users with video operator privileges to upload arbitrary files that can overwrite critical server files. The unrestricted file upload functionality bypasses type validation, enabling attackers to inject malicious scripts and achieve remote code execution.

    Attackers can leverage this vulnerability to escalate privileges to root, fully compromise the Meeting Management server, and gain unauthorized access to sensitive organizational data, meeting recordings, and certificates.

    [:octicons-arrow-right-24: Read more](2026/Week5/cisco.md)

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

-   ![redkitten](2026/Week5/images/redkitten.png)

    **RedKitten — Iran-Linked Cyber-Espionage Campaign**

    **Cyber-Espionage**{.cve-chip} **Macro Malware**{.cve-chip} **SloppyMIO Backdoor**{.cve-chip} **Telegram C2**{.cve-chip} **Spear-Phishing**{.cve-chip}

    RedKitten uses weaponized Excel spreadsheets with malicious macros to install the SloppyMIO backdoor. The files are crafted as sensitive data about protesters or missing persons, pressuring victims to enable macros and triggering infection via AppDomainManager injection.
    
    The malware retrieves configuration hidden in images from GitHub and Google Drive, then uses the Telegram Bot API for C2. Operators can run commands, exfiltrate files, establish persistence, and target civil society organizations.

    [:octicons-arrow-right-24: Read more](2026/Week5/redkitten.md)

-   ![escan](2026/Week5/images/escan.png)

    **eScan Antivirus Update Server Compromise**

    **Supply Chain Compromise**{.cve-chip} **Malicious Update**{.cve-chip} **Persistence**{.cve-chip} **AMSI Bypass**{.cve-chip} **PowerShell**{.cve-chip}

    Attackers gained access to a regional eScan update server and inserted a trojanized update into the official distribution path. The malicious update replaced a legitimate component (Reload.exe) and executed Base64-encoded PowerShell payloads to disable future updates and establish persistence.
    
    A downloader contacted attacker infrastructure for additional payloads, while HOSTS and registry modifications interfered with normal update mechanisms. Affected systems required manual remediation after the Jan 20, 2026 update window.

    [:octicons-arrow-right-24: Read more](2026/Week5/escan.md)

-   ![clawdbot](2026/Week5/images/clawdbot.png)

    **Clawdbot (OpenClaw) 1-Click Remote Code Execution Vulnerability**

    **CVE-2026-25253**{.cve-chip} **Remote Code Execution**{.cve-chip} **1-Click Exploit**{.cve-chip} **Token Hijacking**{.cve-chip} **WebSocket**{.cve-chip}

    A critical vulnerability in Clawdbot AI assistant allows attackers to achieve remote code execution with a single user click. By crafting a malicious URL with a rogue gatewayUrl parameter, attackers can hijack authentication tokens through insecure WebSocket handling when a logged-in user clicks the link.
    
    The stolen token grants full administrative access to the Clawdbot instance, enabling arbitrary command execution on the host system. The flaw affects systems believed to be "localhost-only" due to weak origin checks and implicit trust of local connections.

    [:octicons-arrow-right-24: Read more](2026/Week5/clawdbot.md)

</div>
