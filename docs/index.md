---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

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

</div>
