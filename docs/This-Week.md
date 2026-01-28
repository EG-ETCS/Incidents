---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![protobuf](2026/Week4/images/protobuf.png)

    **Google Protocol Buffers JSON Parsing Denial-of-Service Vulnerability**

    **CVE-2026-0994**{.cve-chip} **Denial-of-Service**{.cve-chip} **JSON Parsing**{.cve-chip} **Python Protobuf**{.cve-chip} **Recursion Bypass**{.cve-chip}

    A high-severity vulnerability in Google Protocol Buffers (protobuf) Python implementation allows attackers to crash applications by sending specially crafted JSON payloads. By abusing deeply nested protobuf Any message types, attackers can bypass built-in recursion limits, leading to uncontrolled recursion and service termination.
    
    The flaw exists in the json_format.ParseDict() function where nested Any messages bypass the recursion counter, causing stack exhaustion and RecursionError. No authentication is required, enabling remote exploitation and persistent denial-of-service attacks against any service parsing untrusted JSON with Python protobuf.

    [:octicons-arrow-right-24: Read more](2026/Week4/protobuf.md)

-   ![office](2026/Week4/images/office.png)

    **Microsoft Office Security Feature Bypass Vulnerability**

    **CVE-2026-21509**{.cve-chip} **Security Feature Bypass**{.cve-chip} **COM/OLE Processing**{.cve-chip} **User Interaction**{.cve-chip} **Zero-Day**{.cve-chip}

    A critical security feature bypass vulnerability in Microsoft Office allows attackers to circumvent built-in security controls designed to block dangerous COM/OLE objects embedded in Office files. The flaw affects Office 2016, 2019, LTSC 2021/2024, and Microsoft 365 Apps for Enterprise.
    
    Exploitation requires user interaction to open a malicious Office document. Once opened, the vulnerability allows attackers to bypass Office security mitigations, potentially leading to unauthorized code execution, malware deployment, data theft, or system compromise. The vulnerability is actively exploited in the wild.

    [:octicons-arrow-right-24: Read more](2026/Week4/office.md)

-   ![winrar](2026/Week4/images/winrar.png)

    **WinRAR Path Traversal Vulnerability**

    **CVE-2025-8088**{.cve-chip} **Path Traversal**{.cve-chip} **Arbitrary Code Execution**{.cve-chip} **Active Exploitation**{.cve-chip} **State-Sponsored**{.cve-chip}

    A critical path traversal flaw in WinRAR allows attackers to craft malicious RAR archives that extract executable payloads to arbitrary locations on the victim's file system, such as Windows Startup folders. The vulnerability affects WinRAR versions up to 7.12 and is actively exploited by both state-aligned threat actors and cybercriminals.
    
    Exploitation occurs through spear-phishing campaigns delivering crafted RAR files that abuse NTFS Alternate Data Streams to bypass extraction boundaries. Once opened, malware is automatically placed in startup directories and executes without further user interaction, establishing persistent backdoor access.

    [:octicons-arrow-right-24: Read more](2026/Week4/winrar.md)

-   ![grist](2026/Week4/images/grist.png)

    **Critical Grist-Core Vulnerability Allows RCE Attacks via Spreadsheet Formulas**

    **CVE-2026-24002**{.cve-chip} **Remote Code Execution**{.cve-chip} **Sandbox Escape**{.cve-chip} **Cellbreak**{.cve-chip} **Pyodide**{.cve-chip}

    A critical vulnerability in Grist-Core allows attackers to achieve remote code execution through malicious Python formulas in spreadsheets. The "Cellbreak" flaw enables crafted formulas to escape the Pyodide WebAssembly sandbox and run arbitrary OS commands or host JavaScript, collapsing the boundary between spreadsheet logic and server execution.
    
    The vulnerability stems from improper sandbox isolation allowing class hierarchy traversal and access to dangerous modules like ctypes. Once escaped, attackers gain complete control over the server process, enabling data theft, credential extraction, and lateral movement within networks.

    [:octicons-arrow-right-24: Read more](2026/Week4/grist.md)

-   ![vm2](2026/Week4/images/vm2.png)

    **vm2 Sandbox Escape Vulnerability**

    **CVE-2026-22709**{.cve-chip} **Sandbox Escape**{.cve-chip} **Arbitrary Code Execution**{.cve-chip} **Node.js**{.cve-chip} **Promise Bypass**{.cve-chip}

    A critical sandbox escape vulnerability in vm2, a popular Node.js library for executing JavaScript in isolated contexts, allows attackers to bypass sandbox restrictions and execute arbitrary code on the host system. The flaw stems from incomplete sanitization of Promise callbacks where globalPromise.prototype.then and catch are not properly sanitized.
    
    Attackers can leverage async functions that return globalPromise objects to attach malicious callbacks, access native constructors, and invoke modules like child_process to execute arbitrary code with full Node.js process privileges. This affects CI/CD pipelines, code execution services, plugin systems, and developer tooling.

    [:octicons-arrow-right-24: Read more](2026/Week4/vm2.md)

-   ![gmail](2026/Week4/images/gmail.png)

    **48 Million Gmail Usernames And Passwords Leaked Online**

    **Data Breach**{.cve-chip} **Credential Exposure**{.cve-chip} **Infostealer Campaign**{.cve-chip} **149M Records**{.cve-chip} **No Encryption**{.cve-chip}

    A massive dataset of 149,404,754 unique usernames and passwords was discovered completely unprotected on a cloud server with no authentication or encryption. The leaked credentials include an estimated 48 million Gmail accounts plus millions from Facebook, Instagram, Netflix, TikTok, and other platforms. 
    
    The dataset appears to be aggregated from infostealer malware campaigns (keylogging and password-stealing software) that collected credentials over extended periods. The repository lacked any access controls, remaining publicly accessible to anyone with the direct link, enabling widespread credential stuffing attacks and identity theft.

    [:octicons-arrow-right-24: Read more](2026/Week4/gmail.md)

-   ![buds](2026/Week4/images/buds.png)

    **Xiaomi Redmi Buds Bluetooth RFCOMM Vulnerabilities**

    **CVE-2025-13834**{.cve-chip} **CVE-2025-13328**{.cve-chip} **Bluetooth Memory Disclosure**{.cve-chip} **Bluetooth DoS**{.cve-chip} **Proximity Exploit**{.cve-chip}

    Critical flaws in the proprietary RFCOMM implementation of Xiaomi Redmi Buds allow nearby, unauthenticated attackers to leak device memory (Heartbleed-style) and force persistent denial-of-service without pairing. 
    
    Malformed RFCOMM messages can expose real-time call data (e.g., phone numbers) or push the earbuds into a broken state until the attack stops.

    [:octicons-arrow-right-24: Read more](2026/Week4/buds.md)

-   ![codebreach](2026/Week4/images/codebreach.png)

    **CodeBreach – AWS CodeBuild Misconfiguration Vulnerability**

    **AWS Misconfiguration**{.cve-chip} **Supply Chain Vulnerability**{.cve-chip} **Regex Filter Bypass**{.cve-chip} **Credential Theft**{.cve-chip} **GitHub Hijacking**{.cve-chip}

    A critical misconfiguration in AWS CodeBuild webhook filters allowed unauthenticated actors to trigger build jobs and access privileged credentials. Improperly anchored regex patterns in ACTOR_ID filters accepted any ID containing an approved ID as a substring, enabling attackers to create GitHub accounts with matching numeric IDs and bypass authentication. 
    
    This could have led to hijacking AWS-managed repositories, injecting malicious code into critical supply chain dependencies, and compromising countless users relying on affected packages globally.

    [:octicons-arrow-right-24: Read more](2026/Week4/codebreach.md)

-   ![amnesia](2026/Week4/images/amnesia.png)

    **Multi-Stage Phishing Campaign Deploying Amnesia RAT and Hakuna Matata Ransomware**

    **Phishing Campaign**{.cve-chip} **Remote Access Trojan**{.cve-chip} **Ransomware**{.cve-chip} **Cloud Abuse**{.cve-chip} **Defender Bypass**{.cve-chip} **Multi-Stage**{.cve-chip}

    A targeted phishing campaign using social engineering and multi-stage malware to compromise Windows systems and deploy both Amnesia RAT (remote access trojan) and Hakuna Matata ransomware. The attack abuses cloud hosting services (GitHub, Dropbox) to host malicious scripts and binaries, and uses the defendnot tool to disable Microsoft Defender. 
    
    Initial delivery occurs via phishing emails with compressed archives and malicious Windows shortcuts using double extensions. The campaign features staged delivery through PowerShell scripts and obfuscated Visual Basic, security tool disablement, reconnaissance via Telegram bots, and dual payload deployment enabling remote control, credential theft, file encryption, and cryptocurrency transaction manipulation.

    [:octicons-arrow-right-24: Read more](2026/Week4/amnesia.md)

-   ![gnu](2026/Week4/images/gnu.png)

    **GNU InetUtils telnetd Remote Authentication Bypass**

    **CVE-2026-24061**{.cve-chip} **Remote Root Access**{.cve-chip} **Authentication Bypass**{.cve-chip} **Legacy Systems**{.cve-chip} **SCADA Threat**{.cve-chip}

    A critical vulnerability in GNU InetUtils telnetd allows unauthenticated attackers to bypass authentication and gain immediate root access by exploiting improper handling of the USER environment variable. The flaw affects versions 1.9.3 through 2.7 and is particularly dangerous on legacy Unix servers, embedded devices, and industrial SCADA systems.
        
    Despite Telnet's known security weaknesses, telnetd remains deployed in manufacturing, energy, and healthcare sectors for compatibility with vintage software. Attackers can simply connect with `USER="-f root"` to bypass login, granting shell access without passwords. Active exploitation emerged within hours of disclosure, with mass scanning and automated exploitation frameworks targeting port 23 globally.

    [:octicons-arrow-right-24: Read more](2026/Week4/gnu.md)

-   ![dynowiper](2026/Week4/images/dynowiper.png)

    **DynoWiper Cyberattack on Polish Energy Systems**

    **Sandworm (APT44)**{.cve-chip} **Wiper Malware**{.cve-chip} **Critical Infrastructure**{.cve-chip} **State-Sponsored**{.cve-chip} **Supply Chain**{.cve-chip}

    A sophisticated destructive cyberattack attributed to Sandworm (Russian military GRU Unit 74455) targeted Polish energy infrastructure with newly identified wiper malware (DynoWiper). The operation aimed to disrupt electricity and heating services to 500,000+ residents during winter months through supply chain compromise of SCADA monitoring software.
        
    Attackers spent 28 days conducting reconnaissance and staging DynoWiper on 46 systems across power substations and control centers. Polish cybersecurity authorities detected the threat before execution and prevented the synchronized wiper attack that would have rendered critical transmission infrastructure inoperable.

    [:octicons-arrow-right-24: Read more](2026/Week4/dynowiper.md)

</div>
