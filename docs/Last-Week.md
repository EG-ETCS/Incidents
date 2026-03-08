---
hide:
  - navigation
  - toc
---

# Last Week's Security Incidents
 
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

-   ![vmware](2026/Week9/images/vmware.png)

    **CISA Flags VMware Aria Operations RCE Flaw as Exploited in Attacks**

    **CVE-2026-22719**{.cve-chip} **Command Injection**{.cve-chip} **KEV Listed**{.cve-chip} **Aria Operations**{.cve-chip}

    CISA added CVE-2026-22719 in VMware Aria Operations to the KEV catalog after confirmed real-world exploitation. The high-severity command injection bug affects migration-related logic and can enable remote code execution in reachable management environments.

    Attackers can use this foothold to tamper with monitoring infrastructure, establish persistence, and potentially pivot deeper into vSphere and hybrid-cloud estates, especially when chained with related XSS and privilege-escalation weaknesses.

    [:octicons-arrow-right-24: Read more](2026/Week9/vmware.md)

-   ![dlink](2026/Week9/images/dlink.png)

    **CVE-2026-3485 — OS Command Injection in SSDP Service of D-Link DIR-868L 110b03**

    **CVE-2026-3485**{.cve-chip} **OS Command Injection**{.cve-chip} **SSDP/UPnP**{.cve-chip} **Unauthenticated RCE**{.cve-chip}

    A command injection vulnerability in the SSDP service of D-Link DIR-868L firmware 110b03 allows attackers to abuse the `ST` parameter and execute arbitrary shell commands without authentication. The flaw is reachable anywhere the vulnerable SSDP service is exposed, including local segments and misconfigured internet-facing paths.

    Successful exploitation can result in full router takeover, traffic interception/manipulation, malware persistence, and botnet enrollment, with elevated long-term risk because the affected platform may no longer receive vendor security fixes.

    [:octicons-arrow-right-24: Read more](2026/Week9/dlink.md)

-   ![BadeSaba](2026/Week9/images/BadeSaba.png)

    **BadeSaba Calendar App Hack (Iranian Prayer-App Compromise)**

    **Mobile App Compromise**{.cve-chip} **Push Notification Abuse**{.cve-chip} **Information Operations**{.cve-chip} **Crisis-Time Targeting**{.cve-chip}

    The BadeSaba Calendar app ecosystem was reportedly compromised, enabling unauthorized push notifications to millions of users with Persian-language messages during active military operations and broad internet disruptions. Reporting indicates likely compromise of push-notification backend/control infrastructure rather than endpoint exploitation.

    The incident highlights how high-reach notification systems can be weaponized for psychological and information operations, especially when synchronization with connectivity outages limits rapid verification through alternative channels.

    [:octicons-arrow-right-24: Read more](2026/Week9/BadeSaba.md)

-   ![simSwap](2026/Week9/images/simSwap.png)

    **Dubai SIM-Swap Scam Exploiting Regional Tensions**

    **SIM-Swap Fraud**{.cve-chip} **Social Engineering**{.cve-chip} **Identity Abuse**{.cve-chip} **Crisis-Themed Scam**{.cve-chip}

    Scammers impersonating a fake “Dubai Crisis Management” authority reportedly targeted residents with urgent calls and messages to harvest UAE Pass and Emirates ID details. The campaign appears designed to enable downstream SIM-swap fraud by social-engineering carriers into transferring victim numbers.

    Once a number is hijacked, attackers can intercept SMS OTP/2FA codes and attempt account takeovers in banking and other sensitive services, amplifying financial and identity risk during a period of regional tension.

    [:octicons-arrow-right-24: Read more](2026/Week9/simSwap.md)

-   ![android](2026/Week9/images/android.png)

    **Android Security Update — March 2026**

    **CVE-2026-21385**{.cve-chip} **Android Security Bulletin**{.cve-chip} **129 CVEs Patched**{.cve-chip} **Actively Exploited**{.cve-chip}

    Google’s March 2026 Android security release patched 129 vulnerabilities, the largest monthly Android fix batch since 2018, including a Qualcomm memory corruption flaw (CVE-2026-21385) reported as actively exploited in limited targeted attacks.

    The update spans framework, system, kernel, and vendor components, with patch levels 2026-03-01 and 2026-03-05. Unpatched or end-of-support devices remain at elevated risk of code execution, privilege escalation, and persistent compromise.

    [:octicons-arrow-right-24: Read more](2026/Week9/android.md)

-   ![dohdoor](2026/Week9/images/dohdoor.png)

    **UAT-10027 Targets U.S. Education and Healthcare with Dohdoor Backdoor**

    **Dohdoor Backdoor**{.cve-chip} **UAT-10027**{.cve-chip} **DoH C2**{.cve-chip} **Healthcare/Education**{.cve-chip}

    An ongoing campaign active since at least December 2025 is targeting U.S. education and healthcare organizations with the previously undocumented Dohdoor backdoor. The infection chain uses phishing-linked PowerShell, staged loaders, DLL sideloading via trusted Windows binaries, and encrypted DNS-over-HTTPS C2 traffic over port 443.

    Post-compromise activity includes in-memory payload execution consistent with Cobalt Strike behavior and evasion techniques that reduce endpoint/network visibility, increasing the risk of persistence, lateral movement, and credential theft.

    [:octicons-arrow-right-24: Read more](2026/Week9/dohdoor.md)

-   ![Juniper](2026/Week9/images/Juniper.png)

    **Juniper Networks PTX Series Router Critical Vulnerability (CVE-2026-21902)**

    **CVE-2026-21902**{.cve-chip} **Remote Code Execution**{.cve-chip} **Unauthenticated**{.cve-chip} **Root Access**{.cve-chip}

    A critical flaw in Junos OS Evolved on PTX Series routers can allow remote unauthenticated attackers to execute code as root due to improper permission assignment in the On-Box Anomaly Detection framework. The vulnerable service is exposed externally by mistake and enabled by default in affected builds.

    Successful exploitation can result in full router takeover, traffic manipulation, and severe operational risk for ISP, telecom, and enterprise backbone environments that depend on PTX routing infrastructure.

    [:octicons-arrow-right-24: Read more](2026/Week9/Juniper.md)

-   ![apex](2026/Week9/images/apex.png)

    **Trend Micro Apex One Critical RCE Vulnerabilities**

    **CVE-2025-71210**{.cve-chip} **CVE-2025-71211**{.cve-chip} **Path Traversal**{.cve-chip} **Apex One**{.cve-chip}

    Trend Micro patched critical Apex One vulnerabilities that can lead to remote code execution on on-premises management servers through path traversal and improper input validation. Attackers may write malicious files to unintended directories and execute them with high privileges.

    Compromise of a security management platform creates a high-trust pivot point, enabling potential malicious policy pushes, protection bypass, lateral movement, and broad ransomware or data-theft impact across managed endpoints.

    [:octicons-arrow-right-24: Read more](2026/Week9/apex.md)

</div>
