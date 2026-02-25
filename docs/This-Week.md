---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![phishing](2026/Week8/images/phishing.png)

    **Phishing Campaign Targets Freight and Logistics Orgs in the US, Europe**

    **Credential Phishing**{.cve-chip} **Logistics Sector**{.cve-chip} **Financially Motivated**{.cve-chip} **Account Takeover**{.cve-chip}

    A financially motivated cybercriminal group targeted freight and logistics organizations across the US and Europe using spoofed portals and multi-stage cloaking infrastructure. The campaign reportedly harvested over 1,600 credential sets, including usernames, passwords, 2FA codes, and business identifiers used in freight operations.

    Attackers used urgent business pretexts to drive victims through redirection chains into pixel-perfect fake login pages, then monetized access through account takeover, payment rerouting, fuel card abuse, and double-brokering fraud.

    [:octicons-arrow-right-24: Read more](2026/Week8/phishing.md)

-   ![solarwinds](2026/Week8/images/solarwinds.png)

    **SolarWinds Serv-U Critical Root Access Vulnerabilities**

    **CVE-2025-40538**{.cve-chip} **CVE-2025-40539**{.cve-chip} **CVE-2025-40540**{.cve-chip} **CVE-2025-40541**{.cve-chip}

    SolarWinds patched four critical flaws in Serv-U MFT and Secure FTP that can allow attackers with administrative access to execute arbitrary code and gain root/system-level control. The vulnerabilities affect both Windows and Linux deployments and were fixed in version 15.5.4.

    Exploitation can enable rogue admin creation, privilege escalation, sensitive file exfiltration, and lateral movement, with potential outcomes including ransomware deployment and business disruption in enterprise transfer environments.

    [:octicons-arrow-right-24: Read more](2026/Week8/solarwinds.md)

-   ![filezen](2026/Week8/images/filezen.png)

    **Active Exploitation of FileZen OS Command Injection Vulnerability (CVE-2026-25108)**

    **CVE-2026-25108**{.cve-chip} **OS Command Injection**{.cve-chip} **CWE-78**{.cve-chip} **KEV Listed**{.cve-chip}

    A high-severity OS command injection flaw in Soliton FileZen allows authenticated users to execute arbitrary system commands when Antivirus Check Option is enabled. The vulnerability is actively exploited in the wild and is listed in CISA's Known Exploited Vulnerabilities catalog.

    Affected versions include FileZen 4.2.1–4.2.8 and 5.0.0–5.0.10, with remediation available in 5.0.11+. Exploitation can lead to host compromise, data exposure, and potential lateral movement in connected enterprise environments.

    [:octicons-arrow-right-24: Read more](2026/Week8/filezen.md)

-   ![mississippi](2026/Week8/images/mississippi.png)

    **Mississippi Hospital System Closes All Clinics After Ransomware Attack**

    **Ransomware**{.cve-chip} **Healthcare**{.cve-chip} **Epic EHR**{.cve-chip} **System Shutdown**{.cve-chip}

    A ransomware attack on the University of Mississippi Medical Center forced the closure of all 35 outpatient clinics statewide and canceled elective procedures for multiple days. The attack encrypted the Epic EHR platform, phones, email, and critical IT systems, forcing UMMC to shut down its network and operate hospitals using manual paper-based procedures.

    Detected on February 19, 2026, the attack demonstrates the severe operational impact ransomware can have on healthcare delivery across an entire state network. Attackers made contact with ransom demands while UMMC works with FBI, CISA, and DHS to investigate the intrusion, restore systems, and determine if patient protected health information was compromised.

    [:octicons-arrow-right-24: Read more](2026/Week8/mississippi.md)

-   ![jackpotting](2026/Week8/images/jackpotting.png)

    **Spitting Cash: ATM Jackpotting Attacks Surged in 2025**

    **ATM Jackpotting**{.cve-chip} **Ploutus Malware**{.cve-chip} **Physical Attack**{.cve-chip} **Financial Crime**{.cve-chip}

    ATM jackpotting attacks surged dramatically in 2025, with the FBI recording over 700 incidents causing $20+ million in losses. Attackers use Ploutus malware combined with physical access via generic master keys to force Windows-based ATMs to dispense cash without legitimate transactions. The attacks target the ATM's cash-dispenser APIs directly, bypassing normal banking flows.

    A DOJ case indicted 54 individuals linked to Venezuelan gang Tren de Aragua for 117 jackpotting attempts causing $5.4M in losses. The attacks exploit weak physical security, legacy Windows systems, and commoditized malware tools that enable low-skill crews to execute rapid cash-outs in under 10 minutes per machine.

    [:octicons-arrow-right-24: Read more](2026/Week8/jackpotting.md)

-   ![honeywell](2026/Week8/images/honeywell.png)

    **CVE-2026-1670 – Authentication Bypass in Honeywell CCTV Cameras**

    **CVE-2026-1670**{.cve-chip} **Authentication Bypass**{.cve-chip} **CCTV Security**{.cve-chip} **Unauthenticated Access**{.cve-chip}

    An authentication bypass flaw in Honeywell CCTV camera models allows attackers to access a password recovery API endpoint without valid credentials. By changing the recovery email to an attacker-controlled address, adversaries can trigger password resets and gain full administrative access to affected devices.

    The vulnerability requires no prior credentials or user interaction—only network reachability of the camera. Supported models include I-HIB2PI-UL, SMB NDAA MVO-3, and PTZ WDR 2MP variants. Exploitation enables unauthorized access to live surveillance feeds, camera controls, and potential network pivoting into adjacent systems.

    [:octicons-arrow-right-24: Read more](2026/Week8/honeywell.md)

-   ![predator](2026/Week8/images/predator.png)

    **Predator Spyware: iOS Mic/Camera Indicator Suppression**

    **Commercial Spyware**{.cve-chip} **iOS Targeting**{.cve-chip} **Surveillance**{.cve-chip} **Covert Recording**{.cve-chip}

    Predator, a sophisticated commercial spyware by Intellexa, can hook into iOS SpringBoard to suppress the green/orange camera and microphone activity indicators, hiding covert surveillance from users. By injecting code into SpringBoard's internal functions and nullifying sensor state update objects, Predator silently disables visual alerts while recording continues undetected.

    Targeting journalists, activists, and political figures, Predator requires kernel-level access and demonstrates how sophisticated spyware subverts fundamental iOS privacy protections. The malware can capture microphone audio, record video, exfiltrate GPS data, and monitor communications without any visual indication to the user.

    [:octicons-arrow-right-24: Read more](2026/Week8/predator.md)

-   ![grandstream](2026/Week8/images/grandstream.png)

    **Critical VoIP Vulnerability in Grandstream GXP1600 Series (CVE-2026-2329)**

    **CVE-2026-2329**{.cve-chip} **Remote Code Execution**{.cve-chip} **VoIP Phone**{.cve-chip} **Call Interception**{.cve-chip}

    A critical unauthenticated stack-based buffer overflow in Grandstream GXP1600 series VoIP phones enables remote code execution with root privileges. By sending a crafted HTTP request to the web API endpoint, attackers can trigger a buffer overflow and execute arbitrary code without any authentication.

    Post-exploitation, attackers extract SIP and local credentials, reconfigure the phone's SIP settings to route calls through malicious proxies, and silently intercept calls while the phone functions normally. These phones serve as stealthy network footholds for eavesdropping on confidential business and government communications.

    [:octicons-arrow-right-24: Read more](2026/Week8/grandstream.md)

-   ![ficoba](2026/Week8/images/FICOBA.png)

    **FICOBA National Bank Account Database Breach (France)**

    **Data Breach**{.cve-chip} **Credential Compromise**{.cve-chip} **Financial Data**{.cve-chip} **Government Database**{.cve-chip}

    A malicious actor used stolen government official credentials to access FICOBA, France's national database recording all bank accounts. Approximately 1.2 million account records were compromised, exposing RIB/IBAN numbers, names, residential addresses, tax IDs, and birth information.

    While no account balances or transaction capability was accessed, the exposure of banking identifiers creates significant risk for fraud, unauthorized direct debits, and identity theft. The breach resulted from insufficient access controls, lack of multi-factor authentication, and inadequate monitoring of sensitive database queries.

    [:octicons-arrow-right-24: Read more](2026/Week8/FICOBA.md)

-   ![fortinet](2026/Week8/images/fortinet.png)

    **Amazon: AI-Assisted Hacker Breached 600 Fortinet Firewalls in 5 Weeks**

    **AI-Assisted Attack**{.cve-chip} **Credential Abuse**{.cve-chip} **FortiGate Firewalls**{.cve-chip} **Financially Motivated**{.cve-chip}

    A Russian-speaking threat actor with limited technical skills used multiple commercial generative AI services to breach over 600 FortiGate firewalls across 55 countries between January 11 and February 18, 2026. Amazon's CISO described the operation as an "AI-powered assembly line for cybercrime," where AI tools handled reconnaissance, scripting, attack planning, and tooling development.

    Crucially, no Fortinet vulnerability was exploited—attacks relied on exposed management interfaces, weak passwords, and lack of MFA. AI services generated attack scripts, analyzed stolen configurations, and guided lateral movement, demonstrating how AI drastically lowers the skill barrier for sophisticated cyber campaigns.

    [:octicons-arrow-right-24: Read more](2026/Week8/fortinet.md)

-   ![iptv](2026/Week8/images/iptv.png)

    **Fake IPTV Apps Spread Massiv Android Malware Targeting Mobile Banking Users**

    **Android Banking Trojan**{.cve-chip} **Mobile Malware**{.cve-chip} **IPTV Lure**{.cve-chip} **Device Takeover**{.cve-chip}

    Massiv is a sophisticated Android banking trojan disguised as fake IPTV streaming apps, targeting users in Portugal, Spain, France, and Turkey. It abuses Android Accessibility Services to enable keylogging, screen overlays, and two remote-control modes: live screen streaming via MediaProjection API and advanced UI-tree extraction that bypasses screen-capture protections.

    Active for 8+ months with upward trends, Massiv enables attackers to steal banking credentials, conduct real-time fraudulent transactions, and open new accounts in victims' names. The malware also targets Portugal's Chave Móvel Digital national authentication system, enabling full identity theft and financial fraud at the national e-ID level.

    [:octicons-arrow-right-24: Read more](2026/Week8/iptv.md)

</div>
