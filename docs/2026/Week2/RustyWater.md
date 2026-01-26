# MuddyWater RustyWater RAT Campaign – Iran-linked APT Espionage
![alt text](images/RustyWater1.png)

**MuddyWater**{.cve-chip} **APT**{.cve-chip} **RustyWater RAT**{.cve-chip} **Rust Malware**{.cve-chip} **Spear-Phishing**{.cve-chip} **Middle East**{.cve-chip}

## Overview

**MuddyWater (aka TEMP.Zagros, Static Kitten, Mango Sandstorm)**, an **Iran-linked advanced persistent threat (APT) group** attributed to Iran's **Ministry of Intelligence and Security (MOIS)**, has launched a sophisticated **spear-phishing campaign** targeting organizations across the **Middle East** with a newly developed **Rust-based remote access trojan (RAT)** dubbed **RustyWater** (also known as **Archer RAT** or **RUSTRIC**). 

This campaign marks a **significant evolution in MuddyWater's tactics**, shifting from their historically preferred PowerShell-based malware to a **compiled Rust binary** that offers **superior stealth, cross-platform portability, and resistance to reverse engineering**. The attack begins with **meticulously crafted spear-phishing emails** impersonating **trusted cybersecurity organizations, government entities, or industry partners**, often using themes related to **"cybersecurity guidelines," "security updates," or "urgent compliance notifications"** to create a false sense of legitimacy and urgency. 

Attached to these emails are **malicious Microsoft Word documents** (.docx, .doc) employing **icon spoofing techniques** to appear as legitimate PDF files, cybersecurity advisories, or official documents, combined with **social engineering text** that convinces victims to **enable macros** (a critical user action required for infection). Once macros are enabled, an **embedded VBA (Visual Basic for Applications) macro** executes, downloading and deploying the **RustyWater RAT binary** from attacker-controlled infrastructure. 

![alt text](images/RustyWater2.png)

The RAT establishes **asynchronous command-and-control (C2) communication** with domains such as **nomercys.it[.]com**, enabling the threat actor to maintain **persistent remote access** while evading network detection through irregular communication patterns. RustyWater incorporates **advanced anti-analysis capabilities** including **debugger detection, virtual machine (VM) detection, and sandbox evasion**, making it difficult for security researchers to analyze and for automated malware sandboxes to detonate. The malware achieves **persistence** by creating **Windows Registry Run keys** that ensure automatic execution at system startup, maintaining access even after system reboots. 

As a **modular RAT platform**, RustyWater provides operators with comprehensive post-compromise capabilities including **system reconnaissance (OS version, security products, network configuration), file system operations (upload/download/execute), remote command execution, credential harvesting, and potential lateral movement** across compromised networks. 

The campaign primarily targets **diplomatic entities, government agencies, financial institutions, telecommunications companies, and critical infrastructure operators** in the **Middle East region**, aligning with Iran's strategic intelligence collection priorities. The use of **Rust programming language** represents a **tactical advantage** for MuddyWater, as Rust binaries are **less commonly analyzed by security researchers** compared to traditional C/C++ malware, and **signature-based antivirus detection** is less mature for Rust-compiled threats. 

Additionally, Rust's **memory safety features reduce malware crashes**, improving operational reliability during long-term espionage operations. This campaign highlights MuddyWater's **continued evolution and adaptation**, maintaining relevance as a formidable nation-state threat actor despite years of public exposure and threat intelligence reporting.

---

## Campaign Specifications

| **Attribute**              | **Details**                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| **Threat Actor**           | MuddyWater (TEMP.Zagros, Static Kitten, Mango Sandstorm, TA450)           |
| **Attribution**            | Iran's Ministry of Intelligence and Security (MOIS)                        |
| **Campaign Name**          | RustyWater RAT Deployment                                                  |
| **Malware Family**         | RustyWater RAT (also: Archer RAT, RUSTRIC)                                |
| **Malware Type**           | Remote Access Trojan (RAT), Backdoor                                       |
| **Programming Language**   | Rust (compiled binary)                                                     |
| **Initial Access Vector**  | Spear-phishing emails with malicious Microsoft Word attachments            |
| **Delivery Mechanism**     | Malicious .docx/.doc files with VBA macros                                 |
| **Execution Method**       | User-initiated macro execution → VBA script → RustyWater binary deployment |
| **Persistence Mechanism**  | Windows Registry Run keys (HKCU\Software\Microsoft\Windows\CurrentVersion\Run) |
| **Command & Control (C2)** | Asynchronous HTTP/HTTPS communication to attacker domains                  |
| **Known C2 Domains**       | nomercys.it[.]com, additional domains rotated regularly                    |
| **C2 Architecture**        | Asynchronous communication (irregular intervals to evade network detection)|
| **Primary Targets**        | Middle East organizations (diplomatic, government, financial, telecom)     |
| **Target Sectors**         | Government, Diplomacy, Finance, Telecommunications, Critical Infrastructure|
| **Campaign Timeline**      | Active as of January 2026 (ongoing)                                        |
| **Attack Complexity**      | Medium (requires user interaction to enable macros, but well-crafted social engineering) |
| **Anti-Analysis Features** | Debugger detection, VM detection, sandbox evasion, code obfuscation        |
| **RAT Capabilities**       | Remote command execution, file operations, system reconnaissance, credential theft, lateral movement potential |
| **Detection Evasion**      | Rust binary (less common in malware landscape), asynchronous C2, anti-VM   |
| **Threat Intelligence**    | Publicly disclosed by CloudSEK, security vendors (January 2026)            |
| **Motivation**             | Espionage, intelligence collection, geopolitical surveillance              |
| **Related Malware**        | Previous MuddyWater tools: PowGoop, Canopy, Mori, POWERSTATS, SimpleHelp  |

---

## Technical Details

### MuddyWater APT Group Background

**MuddyWater Overview**:

- **Active Since**: 2017 (publicly disclosed 2018)
- **Sponsor**: Iran Ministry of Intelligence and Security (MOIS)
- **Aliases**: TEMP.Zagros, Static Kitten, Mango Sandstorm (Microsoft), TA450 (Proofpoint), SeedWorm
- **Historical Targets**: Middle East, Asia, Europe, North America (with focus on Iran's regional adversaries)
- **Typical Victims**: Government agencies, telecommunications, defense contractors, oil & gas, critical infrastructure
- **Previous Tactics**: PowerShell-based malware, compromised websites for C2, legitimate remote admin tools (ScreenConnect, RemoteUtilities)
- **Evolution**: Gradual shift from PowerShell scripts to compiled binaries for better evasion

**Why Rust for Malware Development?**

Rust offers several advantages for APT operations:

- **Cross-Platform**: Compile once, run on Windows, Linux, macOS (potential multi-OS campaigns)
- **Memory Safety**: Prevents crashes from buffer overflows, improving malware stability during long-term operations
- **Performance**: Compiled binaries execute faster than interpreted scripts (PowerShell, Python)
- **Obfuscation**: Rust binaries harder to reverse engineer than C/C++ (different compiler conventions, unfamiliar code structures)
- **Detection Gap**: Antivirus and EDR signatures less mature for Rust malware compared to traditional languages
- **Modern Toolchain**: Active developer community, rich library ecosystem (crates) for networking, cryptography, system APIs

### Attack Chain Overview

```
┌─────────────────────────────────────────────────────────────────┐
│ Phase 1: Spear-Phishing Delivery                           │
│ Victim receives email with malicious Word document         │
│ Social engineering: "Urgent Cybersecurity Guidelines.docx" │
└────────────────────────┬────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│ Phase 2: User Execution & Macro Activation                 │
│ Victim opens document, sees "Enable Content" prompt        │
│ Social engineering text convinces user to enable macros    │
│ VBA macro executes automatically                           │
└────────────────────────┬────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│ Phase 3: RustyWater RAT Deployment                         │
│ VBA macro downloads RustyWater binary from staging server  │
│ Binary saved to %TEMP% or user writable directory          │
│ Macro executes RustyWater.exe                              │
└────────────────────────┬────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│ Phase 4: Persistence & Anti-Analysis                       │
│ RustyWater checks for debuggers, VMs, sandboxes            │
│ If clear: Creates Registry Run key for persistence         │
│ HKCU\Software\Microsoft\Windows\CurrentVersion\Run         │
│ Value: "SecurityUpdate" = "C:\Users\...\RustyWater.exe"    │
└────────────────────────┬────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────┐
│ Phase 5: C2 Communication & Operator Control                │
│ RAT initiates asynchronous HTTPS beacon to nomercys.it[.]com│
│ Sends system info: OS, username, security products          │
│ Receives commands: Execute, Upload, Download, Enumerate     │
│ Operator maintains persistent access for espionage          │
└──────────────────────────────────────────────────────────────────┘
```

## Attack Scenario

### Step-by-Step APT Campaign Execution

1. **Target Selection & Reconnaissance**  
   MuddyWater operators identify high-value targets in Middle East:
    - **Target Profile**: Saudi Arabian Ministry of Foreign Affairs
    - **OSINT Collection**: 
         - LinkedIn profiles of diplomats, IT staff
         - Email addresses harvested from public sources (press releases, conference attendees)
         - Technology stack research (job postings reveal "Microsoft Office 365," "Windows 10")
    - **Target List**: 50 embassy staff, 20 IT administrators, 10 senior diplomats
    - **Operational Goal**: Long-term espionage access to diplomatic communications

2. **Weaponization: Malicious Document Creation**  
   Threat actor crafts spear-phishing lure:
   ```
   Document created:
   Filename: "CISA_Cybersecurity_Guidelines_Diplomatic_Sector_2026.docx"
   
   Content:
   - Official-looking header mimicking CISA (US Cybersecurity & Infrastructure Security Agency)
   - Text: "Recent attacks on diplomatic missions require immediate security updates"
   - Social engineering: "Enable macros to view classified guidelines"
   - Embedded VBA macro containing RustyWater deployment logic
   
   Icon spoofing:
   - Document icon changed to Adobe PDF icon (appears as PDF, actually .docx)
   
   Metadata scrubbing:
   - Author field set to "CISA Security Team" (spoofed)
   - Creation date backdated to appear recent but official
   ```

3. **Delivery: Spear-Phishing Email Campaign**  
   Emails sent to 80 targets across Saudi Foreign Ministry:
    ```
    From: security-alerts@cisa-updates[.]com (spoofed, typosquatting CISA.gov)
    To: ahmed.hassan@mofa.gov.sa (diplomat's email)
    Subject: URGENT: Mandatory Cybersecurity Compliance for Diplomatic Missions
    
    Dear Mr. Hassan,
    
    CISA has identified increased cyber threats targeting diplomatic entities
    in the Middle East region. As part of mandatory security updates, all
    personnel must review the attached guidelines within 48 hours.
    
    Failure to comply may result in restricted access to classified systems.
    
    Attachment: CISA_Cybersecurity_Guidelines_Diplomatic_Sector_2026.docx
    
    Please acknowledge receipt by replying to this email.
    
    Best regards,
    CISA Incident Response Team
    ```
    
    **Email Infrastructure**:
    
    - Domain registered: `cisa-updates[.]com` (typosquatting legitimate cisa.gov)
    - Email server: Compromised mail server in third-party country (cover tracks)
    - Sending time: 9:00 AM local time (business hours, higher open rate)
    
4. **User Execution: Victim Opens Document**  
   Target diplomat receives and opens email:
   ```
   Victim: Ahmed Hassan, Senior Diplomatic Analyst
   
   9:05 AM: Email arrives in Outlook inbox
   9:10 AM: Ahmed sees email, recognizes "CISA" (familiar cybersecurity organization)
   9:12 AM: Opens attachment "CISA_Cybersecurity_Guidelines_Diplomatic_Sector_2026.docx"
   
   Microsoft Word opens document:
   - Yellow security banner appears: "SECURITY WARNING: Macros have been disabled."
   - Button displayed: "Enable Content"
   
   Document content visible (lure text):
   "This document contains dynamic content. To view the full security
   guidelines, click 'Enable Content' above. This action is required
   for proper formatting of classified information."
   
   9:13 AM: Ahmed clicks "Enable Content" button (trusts CISA as legitimate source)
   
   Macros enabled → VBA script executes
   ```

5. **Execution: RustyWater RAT Deployment**  
   VBA macro runs automatically:
   ```
   9:13:05 AM: AutoOpen() macro triggered
   9:13:06 AM: Macro contacts C2 server nomercys.it[.]com
   9:13:08 AM: Downloads RustyWater.exe (3.2 MB) from C2
   9:13:12 AM: Saves to C:\Users\ahmed.hassan\AppData\Local\Temp\SecurityUpdate.exe
   9:13:13 AM: Executes SecurityUpdate.exe via Shell() command
   9:13:14 AM: RustyWater RAT starts execution
   
   RustyWater initialization:
   1. Check for debuggers/VMs (none detected)
   2. Check for EDR products (Windows Defender detected, bypassed via AMSI bypass)
   3. Proceed with malicious operations
   ```

6. **Persistence: Registry Run Key Creation**  
   RustyWater establishes persistence:
   ```
   Registry modification:
   HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
   
   New value created:
   Name: "SecurityUpdate"
   Data: "C:\Users\ahmed.hassan\AppData\Local\Temp\SecurityUpdate.exe"
   
   Result: RustyWater executes automatically every time Ahmed logs into Windows
   
   Windows Event Log entry (if monitored):
   Event ID 13: Registry value set (Sysmon detection point)
   ```

7. **Command & Control: Initial Beacon**  
   RustyWater initiates C2 communication:
   ```
   9:13:20 AM: First beacon sent to nomercys.it[.]com
   
   Beacon payload:
   {
     "bot_id": "a3f5e2d1-4b7c-9e8d-3f1a-2b5c6d7e8f9a",
     "hostname": "MOFA-LAPTOP-057",
     "username": "ahmed.hassan",
     "os": "Windows 10 Enterprise 21H2",
     "ip": "10.250.12.50",
     "antivirus": "Windows Defender",
     "domain": "mofa.gov.sa",
     "admin": false,
     "installed_software": ["Microsoft Office 2019", "VPN Client", "Outlook"],
     "processes": ["outlook.exe", "chrome.exe", "teams.exe"]
   }
   
   C2 operator receives new victim notification:
   "New bot: Saudi Foreign Ministry diplomat, no admin rights, Windows Defender"
   
   C2 response: "Acknowledged. Begin reconnaissance phase."
   ```

8. **Post-Compromise: System Reconnaissance**  
   Operator issues reconnaissance commands:
   ```
   Command 1: Enumerate network shares
   > net view /domain
   > net view \\fileserver01
   
   Result: Discovers shared drives with diplomatic cables, reports, correspondence
   
   Command 2: Enumerate domain users
   > net user /domain
   > net group "Domain Admins" /domain
   
   Result: Identifies 5 domain admin accounts, 200+ user accounts
   
   Command 3: List scheduled tasks
   > schtasks /query /fo LIST
   
   Result: Discovers automated backup tasks, reveals backup server location
   
   Command 4: Enumerate email
   > powershell -c "Get-ChildItem -Path 'C:\Users\ahmed.hassan\AppData\Local\Microsoft\Outlook' -Filter *.ost"
   
   Result: Locates Outlook data file (email archive)
   ```

9. **Data Exfiltration: Stealing Sensitive Documents**  
   Operator targets diplomatic communications:
   ```
   Exfiltration commands:
   
   1. Search for sensitive files
   > dir /s /b C:\Users\ahmed.hassan\Documents\*.docx
   > dir /s /b C:\Users\ahmed.hassan\Documents\*classified*
   > dir /s /b C:\Users\ahmed.hassan\Desktop\*cable*
   
   2. Upload files to C2
   Files uploaded:
   - "US_Iran_Negotiations_Summary_Jan2026.docx" (5.2 MB)
   - "Regional_Security_Assessment_Q1_2026.pdf" (12.8 MB)
   - "Diplomatic_Cables_Archive_2025.zip" (450 MB)
   - "Contact_List_Foreign_Diplomats.xlsx" (1.1 MB)
   
   3. Exfiltrate Outlook email archive
   > C:\...\SecurityUpdate.exe --exfil-outlook
   Uploads: ahmed.hassan.ost (8.5 GB) → Split into chunks, upload over 3 days
   
   Total exfiltrated: ~9 GB of diplomatic intelligence
   ```

10. **Lateral Movement & Long-Term Espionage**  
    Operator expands access across network:
    ```
    Week 1: Maintain access on Ahmed's laptop, exfiltrate documents
    
    Week 2: Credential harvesting
    - Extract saved passwords from Chrome (finds credentials for internal SharePoint)
    - Harvest NTLM hashes via Mimikatz (downloaded as additional module)
    - Credential reuse: Login to internal file server using Ahmed's credentials
    
    Week 3: Lateral movement
    - Use harvested credentials to access file server: \\fileserver01\DiplomaticArchive
    - Deploy additional RustyWater instance on file server (persistent access point)
    - Exfiltrate: 50 GB of historical diplomatic cables (2020-2026)
    
    Week 4: Target high-value accounts
    - Phishing campaign targeting IT administrators (need domain admin access)
    - 2 IT admins fall victim → Domain admin credentials obtained
    - Access to Domain Controller: Full visibility into entire MOFA network
    
    Month 2-6: Long-term espionage
    - Persistent monitoring of diplomatic communications
    - Real-time intelligence on negotiations, policy decisions, regional strategy
    - Exfiltration of classified intelligence reports
    - No detection by security team (asynchronous C2, Rust binary evades signatures)
    
    Operational Impact:
    - Iran gains strategic intelligence advantage in regional geopolitics
    - Knowledge of Saudi Arabia's negotiating positions in regional conflicts
    - Identification of foreign intelligence sources and methods
    - Compromise of diplomatic relationships (leaked communications)
    ```

---

## Impact Assessment

=== "Confidentiality"
    Massive intelligence loss and diplomatic compromise:

    - **Diplomatic Communications**: Theft of classified cables, negotiation strategies, policy discussions, intelligence assessments
    - **Geopolitical Intelligence**: Access to regional security strategies, military cooperation plans, economic policies affecting Iran's interests
    - **Source Protection Failure**: Exposure of foreign intelligence sources, human assets, liaison relationships with allied nations
    - **Classified Documents**: Exfiltration of Top Secret/Secret reports on Middle East security, terrorism, nuclear programs
    - **Personal Privacy**: Email archives, contact lists, personal communications of diplomats exposed
    - **Credential Theft**: Passwords, authentication tokens, VPN credentials harvested from compromised systems
    - **Network Mapping**: Complete reconnaissance of government network architecture, security controls, critical systems
    
    Confidentiality breach provides Iran with **years of strategic intelligence**, undermining national security and diplomatic standing.

=== "Integrity"
    Potential for data manipulation and false flag operations:

    - **Document Tampering**: RAT capable of modifying files—could alter diplomatic cables to create false narratives or sow confusion
    - **Email Manipulation**: Access to email accounts enables sending falsified communications from trusted diplomatic sources
    - **False Intelligence**: Injecting fabricated documents into file shares to mislead foreign policy decisions
    - **Reputation Damage**: Leaked authentic communications published online damage diplomatic relationships and trust
    - **Malware Planting**: Deployment of additional payloads (ransomware, destructive malware) if operation shifts from espionage to sabotage
    - **Backdoor Accounts**: Creation of persistent admin accounts for long-term access even after cleanup attempts
    
    While primary objective is espionage (read-only intelligence collection), RAT capabilities enable **active manipulation if operational priorities change**.

=== "Availability"
    Limited direct availability impact, but potential for escalation:

    - **Operational Disruption**: If detected, incident response activities (system quarantine, forensics, rebuilds) disrupt normal operations
    - **Ransomware Threat**: RAT could deploy ransomware as follow-on attack, encrypting diplomatic systems and demanding payment
    - **Resource Consumption**: Large-scale data exfiltration (9+ GB) consumes network bandwidth, potentially impacting performance
    - **System Instability**: Malware bugs or aggressive reconnaissance commands could crash systems or cause service outages
    - **Recovery Costs**: Post-compromise remediation requires extensive effort (reimaging workstations, password resets, network segmentation review)
    
    Availability primarily at risk if operation escalates from **espionage to destructive attack** (geopolitical crisis scenario).

=== "Scope" 
    Impact extends across diplomatic, intelligence, and national security domains:

    - **Government Agencies**: Foreign ministry, defense ministry, intelligence services, national security council
    - **Critical Infrastructure**: Telecommunications, energy, finance sectors targeted in parallel campaigns
    - **Regional Allies**: Compromised diplomatic communications expose allied nations' intelligence, damaging trust and cooperation
    - **International Relations**: Leaked negotiations undermine diplomatic efforts, reveal strategic positions to adversaries
    - **Economic Impact**: Intelligence on trade policies, sanctions strategies, investment plans advantages Iranian economic positioning
    - **Military Operations**: Exposure of military cooperation plans, joint exercises, defense agreements weakens collective security
    - **Long-Term Strategic Disadvantage**: Years of intelligence collection enable Iran to anticipate and counter regional policies
    
    Scope encompasses **entire Middle East geopolitical landscape**, affecting Saudi Arabia's national security, regional alliances, and global standing.

---

## Mitigation Strategies

### Email Security (Preventive)

- **Advanced Email Filtering**: Block malicious attachments:
  ```
  Email Gateway Rules:
  - Block all .doc/.docx files with macros from external senders
  - Sandbox all Office documents before delivery (Proofpoint, Mimecast, FireEye Email Security)
  - Block typosquatting domains (cisa-updates.com vs. legitimate cisa.gov)
  - Implement DMARC, SPF, DKIM to prevent email spoofing
  - Quarantine emails with urgent language ("URGENT," "CLASSIFIED," "MANDATORY")
  ```

- **Attachment Scanning**: Deep inspection of Office documents:
  ```
  Security Tools:
  - YARA rules to detect malicious VBA macros
  - Static analysis: Extract and analyze macro code before delivery
  - Dynamic analysis: Detonate in sandbox environment
  - Block documents with suspicious macro patterns:
    * AutoOpen(), Document_Open() functions
    * Shell(), WScript.Shell execution
    * MSXML2.XMLHTTP network requests
    * Encoded/obfuscated macro code
  ```

- **Macro Policies**: Disable macros by default (Group Policy):
  ```
  Group Policy Settings:
  Computer Configuration → Administrative Templates → Microsoft Office → Security Settings
  
  Setting: "Disable all macros except digitally signed macros"
  or
  Setting: "Disable all macros with notification" (user cannot enable)
  
  Registry key (enforce via GPO):
  HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security
  VBAWarnings = 3 (disable all macros except digitally signed)
  ```

### User Awareness Training

- **Phishing Recognition Training**:
  ```
  Training Curriculum:
  - Recognize spear-phishing red flags:
    * Unsolicited attachments from unknown/external senders
    * Urgent language creating false sense of pressure
    * Requests to "enable macros" or "enable content"
    * Typosquatting domains (cisa-updates.com vs. cisa.gov)
    * Generic greetings ("Dear User" vs. personalized)
  
  - Safe practices:
    * NEVER enable macros in unsolicited documents
    * Verify sender identity via separate communication channel (phone call)
    * Report suspicious emails to security team immediately
    * Use "Report Phishing" button in Outlook/Gmail
  ```

- **Simulated Phishing Exercises**:
  ```
  Regular Testing:
  - Monthly simulated phishing campaigns (Gophish, KnowBe4)
  - Metrics: Click rate, enable-macro rate, reporting rate
  - Remedial training for users who fail simulations
  - Track improvement over time
  ```

### Endpoint Detection & Response (EDR)

- **Deploy EDR Solutions**: Behavioral detection for Rust malware:
  ```
  Recommended EDR Products:
  - CrowdStrike Falcon
  - Microsoft Defender for Endpoint
  - SentinelOne
  - Carbon Black (VMware)
  - Palo Alto Cortex XDR
  
  EDR Detection Capabilities:
  - Behavioral analysis (unusual network connections, file operations)
  - Process tree analysis (Word → PowerShell → unknown .exe)
  - Registry monitoring (Run key modifications)
  - Memory analysis (detect in-memory malware, reflective DLL injection)
  - Machine learning (anomaly detection for Rust binaries)
  ```

- **EDR Detection Rules**: Specific to RustyWater TTPs:
  ```
  Alert Rule 1: Office application spawning suspicious process
  IF winword.exe OR excel.exe
    SPAWNS powershell.exe OR cmd.exe OR wscript.exe OR .exe from %TEMP%
  THEN Alert: "Potential macro-based malware execution"
  
  Alert Rule 2: Registry Run key creation
  IF Registry modification
    AT HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    BY non-administrative process
  THEN Alert: "Persistence mechanism detected"
  
  Alert Rule 3: Unusual external network connections
  IF Process NOT IN trusted_list
    CONNECTS TO external_ip
    WITH User-Agent: "Mozilla/5.0"
  THEN Alert: "Potential RAT C2 communication"
  
  Alert Rule 4: Rust binary execution from temp directory
  IF Executable
    FROM %TEMP% OR %APPDATA%
    WITH File_Characteristics: "Rust compiled binary"
  THEN Alert: "Suspicious Rust malware execution"
  ```

### Network Security Controls

- **C2 Domain Blocking**: Block known MuddyWater infrastructure:
  ```
  DNS Sinkhole / Firewall Block List:
  - nomercys.it[.]com
  - [Additional MuddyWater C2 domains from threat intelligence feeds]
  
  Use Threat Intelligence Feeds:
  - AlienVault OTX
  - MISP (Malware Information Sharing Platform)
  - Recorded Future
  - Vendor-specific feeds (CrowdStrike, Mandiant, Microsoft)
  
  Update firewall/proxy block lists daily with latest IOCs
  ```

- **Outbound Traffic Monitoring**: Detect asynchronous C2 beaconing:
  ```
  Network Detection Rules (IDS/IPS):
  - Alert on HTTPS connections to newly registered domains (< 30 days old)
  - Alert on periodic beaconing patterns (connections every 5-15 minutes)
  - Alert on large outbound data transfers from unexpected processes
  - Alert on connections to hosting providers commonly used for malicious infrastructure
    (e.g., Choopa, Namecheap, DigitalOcean without business justification)
  ```

- **Network Segmentation**: Limit lateral movement:
  ```
  Segmentation Strategy:
  - User workstations in separate VLAN from servers
  - Restrict workstation-to-workstation communication (prevent lateral spread)
  - Firewall rules: Workstations can only reach servers via specific ports/protocols
  - Critical systems (DCs, file servers) in protected VLAN with strict ACLs
  - Monitor East-West traffic (internal) for anomalies
  ```

### Patch Management & Hardening

- **Windows Security Updates**: Prevent macro-based attacks:
  ```
  Enable Windows Security Features:
  - Windows Defender Application Control (WDAC): Block unsigned executables
  - Attack Surface Reduction (ASR) rules:
    * Block Office applications from creating child processes
    * Block Office applications from injecting code into other processes
    * Block executable content from email client and webmail
  
  PowerShell command to enable ASR rules:
  Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
  # This blocks Office apps from creating executables
  ```

- **Application Whitelisting**: Prevent unauthorized executable execution:
  ```
  AppLocker Policy:
  - Allow executables only from:
    * C:\Windows\*
    * C:\Program Files\*
    * C:\Program Files (x86)\*
  - Block executables from:
    * %TEMP%
    * %APPDATA%
    * C:\Users\*\Downloads
  
  WDAC (Windows Defender Application Control):
  - Enforce "Allow Microsoft" + "Allow Store Apps" policy
  - Require code signing for all executables
  - Block Rust binaries unless explicitly whitelisted
  ```

---

## Resources

!!! info "Threat Intelligence Reports"
    - [MuddyWater Launches RustyWater RAT via Spear-Phishing Across Middle East Sectors](https://thehackernews.com/2026/01/muddywater-launches-rustywater-rat-via.html)
    - [MuddyWater Deploys RustyWater RAT in Spear-Phishing Attacks Targeting Middle East Sectors - BinaryPH](https://binary.ph/2026/01/10/muddywater-deploys-rustywater-rat-in-spear-phishing-attacks-targeting-middle-east-sectors/)
    - [CloudSEK warns Muddy Water APT using Rust implants in spearphishing on Middle East critical infrastructure - Industrial Cyber](https://industrialcyber.co/ransomware/cloudsek-warns-muddy-water-apt-using-rust-implants-in-spearphishing-on-middle-east-critical-infrastructure/)
    - [MuddyWater Launches RustyWater RAT via Spear-Phishing Across Middle East Sectors - Live Threat Intelligence - Threat Radar | OffSeq.com](https://radar.offseq.com/threat/muddywater-launches-rustywater-rat-via-spear-phish-e42d1e2e)
    - [MuddyWater APT Weaponizing Word Documents to Deliver 'RustyWater' Toolkit Evading AV and EDR Tools](https://cybersecuritynews.com/muddywater-apt-weaponizing-word-documents/)

---

*Last Updated: January 11, 2026*
