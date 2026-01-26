# UAT-7290 China-Linked Telecom Espionage Campaign

**UAT-7290**{.cve-chip} **China APT**{.cve-chip} **Telecom Espionage**{.cve-chip} **Linux Malware**{.cve-chip} **Operational Relay Box**{.cve-chip} **Critical Infrastructure**{.cve-chip}

## Overview

**UAT-7290**, a **China-linked advanced persistent threat (APT) group** attributed by Cisco Talos Intelligence to **Chinese state-sponsored cyber operations**, has conducted an extensive **multi-year cyber-espionage campaign** targeting **telecommunications providers and critical infrastructure** across **South Asia, Southeastern Europe**. The campaign, ongoing since at least **2020** and actively continuing through **January 2026**, demonstrates sophisticated tradecraft focused on **long-term persistent access, signals intelligence (SIGINT) collection, and infrastructure hijacking** for operational purposes. 

UAT-7290 (Unattributed Threat Actor 7290) specializes in compromising **Linux-based edge networking equipment and core telecommunications infrastructure**—including **routers, firewalls, VPN gateways, SSH jump servers, and network management systems**—that form the backbone of global telecommunications networks. Unlike typical financially-motivated cybercrime or ransomware operations, UAT-7290's objectives align with **strategic intelligence collection and network surveillance** in support of Chinese national security interests, particularly targeting regions of geopolitical importance to China's **Belt and Road Initiative (BRI), territorial disputes (South China Sea, India-China border), and strategic competition with Western telecommunications infrastructure**. 

The group employs a **modular malware ecosystem** consisting of **multiple custom Linux backdoors and toolsets** deployed in coordinated stages: **RushDrop (also known as ChronosRAT)** serves as the initial dropper establishing first foothold, **DriveSwitch** functions as a secondary payload loader, **SilentRaid (MystRodX)** provides comprehensive remote access and control capabilities, and **Bulbature** transforms compromised systems into **Operational Relay Boxes (ORBs)**—essentially proxy infrastructure that UAT-7290 reuses for **anonymizing command-and-control (C2) communications, lateral movement across victim networks, and future campaign staging**. 

The ORB technique is particularly sophisticated: once a telecom edge device is compromised and converted to an ORB, it becomes part of UAT-7290's **permanent infrastructure**, enabling the group to route traffic through legitimate telecommunications infrastructure (making attribution difficult) and maintain access even if the original victim organization implements security improvements on internal systems. Initial access vectors include **exploitation of one-day vulnerabilities** (publicly disclosed CVEs in networking equipment from vendors like Cisco, Juniper, Fortinet, Palo Alto Networks, targeting the window between patch release and enterprise deployment), **SSH brute-force attacks** against exposed management interfaces with weak credentials, and suspected **supply chain compromises** (pre-positioned access via compromised software updates or vendor relationships). UAT-7290's targeting is **highly selective and strategic**, focusing on **telecommunications providers** (mobile carriers, internet backbone providers, undersea cable operators), **government communications infrastructure** (ministries, military networks, intelligence agencies), **defense contractors**, and **critical infrastructure operators** (energy, transportation, utilities) in countries where China maintains active geopolitical and economic interests. 

The campaign's impact extends beyond traditional espionage: by compromising telecommunications infrastructure, UAT-7290 gains potential visibility into **call detail records (CDRs), SMS metadata, internet traffic routing, VPN connections, and subscriber location data**—enabling **mass surveillance, targeted monitoring of individuals of interest (dissidents, journalists, government officials, military personnel), economic espionage (trade secrets, contract negotiations), and strategic intelligence** on regional political developments. The campaign employs advanced **anti-detection and persistence techniques** including **rootkit-like hiding mechanisms** (concealing malware in obscure system directories like `.pkgdb` disguised as package management files), **encrypted C2 communications** (custom protocols, DNS tunneling, HTTPS masquerading), **living-off-the-land tactics** (leveraging legitimate system binaries like `bash`, `ssh`, `curl` to minimize forensic footprints), and **intermittent callback patterns** (dormant periods to evade network anomaly detection). 

UAT-7290 also deploys **Windows malware** for targeted post-exploitation on administrative workstations, including **ShadowPad** (notorious modular backdoor used by multiple Chinese APT groups) and **RedLeaves (BUGJUICE)**, indicating coordination with or shared toolsets from established Chinese cyber espionage units such as **APT41 (Winnti), APT10 (Stone Panda), and APT27 (Emissary Panda)**. 

The telecommunications industry presents a particularly lucrative target for nation-state espionage: telecom providers sit at the nexus of **global communications infrastructure**, handling voice, data, and internet traffic for millions of subscribers, governments, and enterprises. Compromising a single major telecommunications provider can yield intelligence access equivalent to thousands of individual device compromises, and enables **passive surveillance** (simply monitoring traffic flowing through compromised network equipment without needing to infect individual endpoints). 

UAT-7290's multi-year persistence indicates the campaign's high value to Chinese intelligence priorities and the difficulty telecom defenders face in detecting and removing sophisticated Linux-based implants on edge networking devices (which often lack robust logging, security tooling, and are difficult to patch without service disruption). The **Operational Relay Box (ORB) strategy** is particularly concerning from a cybersecurity community perspective: compromised telecom infrastructure becomes **persistent, resilient, and reusable** attack infrastructure that can support not just UAT-7290's operations but potentially be shared across Chinese intelligence agencies or contracted offensive cyber units. 

ORBs enable **traffic laundering** (routing malicious traffic through legitimate telecom infrastructure to conceal attacker origin), **infrastructure hijacking** (turning victim assets into attacker assets), and **long-term strategic positioning** (maintaining access for future contingencies such as pre-positioning for cyberwarfare capabilities in the event of geopolitical conflict). This campaign highlights critical vulnerabilities in **global telecommunications security posture**: many edge networking devices run **outdated firmware**, have **inadequate logging and monitoring**, rely on **weak authentication** (default credentials, password-based SSH), lack **Linux-compatible endpoint detection and response (EDR) tools**, and are managed by **small security teams** unable to keep pace with sophisticated nation-state threats. For telecom providers in developing regions (South Asia, Southeastern Europe), resource constraints and competing operational priorities often result in **delayed patching, insufficient security controls, and limited incident response capabilities**—creating ideal conditions for persistent APT campaigns like UAT-7290.

---

## Campaign Specifications

| **Attribute**              | **Details**                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| **Threat Actor**           | UAT-7290 (Unattributed Threat Actor 7290)                                  |
| **Attribution**            | China-linked (state-sponsored, likely PLA or Ministry of State Security)   |
| **Campaign Type**          | Long-term cyber-espionage targeting telecommunications infrastructure       |
| **Campaign Timeline**      | Active since at least 2020, ongoing through January 2026                    |
| **Primary Target Geography**| South Asia , Southeast Asia  |
| **Target Sectors**         | Telecommunications providers, government communications, defense, critical infrastructure |
| **Target Organizations**   | Mobile carriers, ISPs, undersea cable operators, government ministries, military networks, defense contractors |
| **Strategic Objectives**   | Signals intelligence (SIGINT) collection, mass surveillance, economic espionage, strategic positioning |
| **Initial Access Vectors** | One-day vulnerability exploitation (networking equipment CVEs), SSH brute-force attacks, suspected supply chain compromise |
| **Primary OS Targeting**   | Linux (edge networking devices, routers, firewalls, VPN gateways, SSH jump servers) |
| **Secondary OS Targeting** | Windows (administrative workstations, network management systems)          |
| **Linux Malware Arsenal**  | RushDrop/ChronosRAT (dropper), DriveSwitch (loader), SilentRaid/MystRodX (backdoor), Bulbature (ORB backdoor) |
| **Windows Malware Arsenal**| ShadowPad (modular backdoor), RedLeaves/BUGJUICE (RAT)                     |
| **Key Innovation**         | Operational Relay Box (ORB) technique—converting compromised infrastructure into persistent proxy/relay nodes |
| **C2 Infrastructure**      | Multi-layered: Direct C2 servers, compromised ORBs as intermediaries, DNS tunneling, HTTPS masquerading |
| **Persistence Mechanisms** | Rootkit-like hiding (hidden directories), cron jobs, init scripts, SSH key injection |
| **Stealth Techniques**     | Encrypted C2, intermittent callbacks, living-off-the-land binaries, process hiding |
| **Lateral Movement**       | SSH pivoting via compromised jump servers, ORB-based traffic relaying       |
| **Data Exfiltration**      | Call detail records (CDRs), SMS metadata, VPN logs, network configurations, subscriber data |
| **Intelligence Value**     | Mass surveillance capability, targeted monitoring, economic intelligence, strategic positioning for cyberwarfare |
| **Threat Actor Maturity**  | Highly sophisticated (multi-year operations, modular malware, advanced persistence) |
| **Shared Tooling**         | ShadowPad, RedLeaves used by multiple Chinese APT groups (APT41, APT10, APT27) |
| **Attribution Confidence** | High (infrastructure, tooling, targeting align with Chinese state interests)|
| **Geopolitical Context**   | China's Belt and Road Initiative (BRI), India-China border tensions, South China Sea disputes, regional influence competition |
| **Discovery Source**       | Cisco Talos Intelligence (January 2026 public disclosure)                   |
| **Campaign Codename**      | None publicly assigned (referred to by threat actor ID: UAT-7290)          |

---

## Technical Details

### Target Infrastructure: Telecommunications Edge and Core Systems

**What Makes Telecom Infrastructure Attractive to APTs?**

Telecommunications networks are **strategic intelligence goldmines**:

```
Telecom Infrastructure Value for Espionage:

1. Mass Surveillance Capability:
   - Call Detail Records (CDRs): Who called whom, when, duration
   - SMS metadata: Sender, recipient, timestamp (content if unencrypted)
   - Location data: Cell tower triangulation (track individuals in real-time)
   - Internet traffic metadata: DNS queries, connection patterns, VPN usage
   
2. Targeted Monitoring:
   - Government officials: Monitor cabinet ministers, military leaders
   - Journalists: Identify sources, track investigations
   - Dissidents: Surveillance for authoritarian partner states
   - Competitors: Economic espionage on trade negotiations, contracts
   
3. Strategic Access:
   - Undersea cable taps: Intercept international communications
   - Backbone routing: Visibility into entire country's internet traffic
   - VPN gateways: Decrypt or monitor corporate communications
   - Emergency services: Monitor 911/police/ambulance calls
   
4. Infrastructure Hijacking:
   - DDoS launch platform: Massive bandwidth for cyberattacks
   - Traffic laundering: Route attacks through legitimate telecom IPs
   - Operational relay boxes (ORBs): Persistent proxy infrastructure
   - Pre-positioning: Cyberwarfare capabilities for future conflicts
```

**UAT-7290 Target Systems**:

| **System Type** | **Examples** | **Why Targeted** | **Intelligence Value** |
|----------------|-------------|------------------|----------------------|
| Edge routers | Cisco ASR, Juniper MX Series | First point of entry, handles all traffic | Full traffic visibility, routing manipulation |
| Firewalls | Palo Alto, Fortinet FortiGate | Security perimeter, VPN termination | Decrypt VPN traffic, bypass security controls |
| SSH jump servers | Linux bastion hosts | Access to internal management network | Lateral movement, credential harvesting |
| VPN concentrators | Cisco AnyConnect, OpenVPN | Remote access gateway | Capture VPN credentials, monitor remote workers |
| Network management | OSS/BSS systems | Controls entire telecom network | Configuration access, subscriber database |
| Core network elements | MSC, HLR/HSS, SGW/PGW | Handles voice/SMS/data routing | Real-time interception capability |

---

## Attack Scenario

### Step-by-Step UAT-7290 Telecom Compromise

1. **Target Identification & Reconnaissance**  
   UAT-7290 selects high-value telecommunications target:
      - **Target Profile**: Major South Asian telecommunications provider serving 15 million mobile and 5 million broadband subscribers
      - **Strategic Value**: Primary carrier for government communications and military personnel
      - **Intelligence Objectives**: Monitor government officials, track dissidents, collect call detail records
      - **Reconnaissance Activities**: 
        - Social media analysis to identify network engineers and security team members
        - Job posting analysis reveals equipment vendors (Cisco ASR routers, Fortinet firewalls)
        - DNS enumeration discovers exposed management interfaces
        - Internet scanning tools identify SSH and HTTP services on network devices
        - Historical breach data indicates weak SSH password practices

2. **Vulnerability Scanning & Exploitation**  
   Attacker identifies entry point through recently disclosed vulnerability:
      - **Vulnerability Window**: Cisco releases critical security advisory for IOS XE web UI authentication bypass (CVSS 9.8)
      - **Attacker Response Timeline**:
        - Day 0: Reverse-engineer security patch and develop working exploit
        - Day 1: Scan internet for vulnerable Cisco ASR routers
        - Day 3: Identify target's edge routers running vulnerable software
        - Day 5: Exploit during patching window before target completes testing and deployment
      - **Exploitation**: Attack occurs at 2:30 AM local time during low-activity period
      - **Result**: Root-level access established on Cisco ASR edge router running Linux-based IOS XE

3. **Initial Foothold & Persistence (RushDrop Deployment)**  
   Attacker deploys first-stage dropper:
      - **Initial Reconnaissance**: Attacker enumerates system details, network interfaces, routing tables
      - **RushDrop Installation**: Dropper creates hidden persistence directory, downloads payload loader, installs scheduled task for persistence
      - **C2 Establishment**: Backdoor establishes encrypted connection to attacker infrastructure
      - **Intelligence Gathering**: System reconnaissance data exfiltrated via DNS tunneling
      - **Anti-Forensics**: Attacker removes installation artifacts and clears command history
      - **Result**: Persistent backdoor survives reboots and checks in every 15 minutes

4. **Payload Staging (DriveSwitch Loader)**  
   Second-stage loader fetches modular malware:
      - **Module Retrieval**: DriveSwitch connects to C2 server and downloads malware modules
      - **Available Modules**: SilentRaid backdoor, Bulbature ORB relay, packet capture tools, credential harvesters
      - **Installation**: Encrypted payloads decrypted and installed to hidden system directories
      - **Service Activation**: SilentRaid backdoor and Bulbature ORB services started
      - **Result**: Full backdoor capabilities established with encrypted TLS command-and-control channel

5. **Internal Network Reconnaissance (SilentRaid)**  
   Comprehensive intelligence gathering:
      - **Network Mapping**: Discovery of internal management network with 47 hosts identified
      - **Target Identification**: High-value systems located including network management servers, Windows admin workstations, file servers
      - **Credential Harvesting**: Password hashes stolen, SSH private keys discovered
      - **Configuration Theft**: Router configurations, network topology, BGP peers, VPN tunnels, access control lists captured
      - **Intelligence Exfiltration**: Reconnaissance data packaged and transmitted to attacker infrastructure

6. **Lateral Movement to Core Systems**  
   Pivot to high-value internal targets:
      - **Target Selection**: Network Management System identified as critical asset
      - **Authentication**: Stolen SSH keys used to authenticate to internal servers
      - **Access Gained**: Successful login to network management server with access to all device configurations, billing database, VPN credentials, monitoring dashboards
      - **Secondary Infection**: SilentRaid backdoor deployed on management server with cron-based persistence
      - **Database Access**: Connection established to billing database containing 2.4 billion call detail records spanning 5 years
      - **Data Sampling**: Initial exfiltration of 1 million recent CDR records for analysis

7. **ORB Conversion & Infrastructure Hijacking (Bulbature)**  
   Convert compromised edge router into operational relay box:
      - **ORB Configuration**: Listener established on port 443 with stolen TLS certificate
      - **Authentication**: Pre-shared key cryptographic authentication implemented
      - **Relay Targets**: Whitelist created for approved relay destinations (admin workstations, file servers, core network elements)
      - **Traffic Statistics**: First 24 hours show 47 connections relayed with 2.3 GB data transferred
      - **Attack Chain**: Attacker traffic now routes through compromised telecom router instead of direct connections
      - **Benefits**: Traffic appears legitimate, difficult attribution, resilient infrastructure, supports multiple simultaneous campaigns

8. **Signals Intelligence Collection (CDR Exfiltration)**  
   Mass surveillance data harvesting:
      - **Target Data Sets**:
        - **Call Detail Records**: 350 million records for last 6 months (caller, recipient, timestamp, duration, cell tower location) - 45 GB compressed
        - **SMS Metadata**: 1.2 billion messages for last 3 months (sender, recipient, timestamp) - 12 GB compressed
        - **Subscriber Database**: 15 million records (names, national IDs, addresses, phone numbers, device identifiers) - 3 GB
        - **VPN Logs**: Government employee access patterns, login times, source IPs, accessed resources
      - **Exfiltration Method**: Throttled bandwidth at 10 Mbps maximum during off-peak hours (2:00-6:00 AM), encrypted TLS tunnel, fragmented transfers over 8 nights
      - **Total Exfiltrated**: 60 GB of intelligence data
      - **Detection Status**: No alerts triggered, transfers blend with normal network traffic

9. **Windows Targeting (ShadowPad Deployment)**  
   Compromise administrative workstations:
      - **Target System**: Windows admin workstation used for network management, email, documentation
      - **Access Method**: RDP connection through ORB relay using harvested credentials
      - **Deployment Technique**: Trojanized Windows update delivered via social engineering through compromised email account
      - **Infection Vector**: Administrator executes fake security update containing ShadowPad backdoor
      - **Persistence**: Registry run key and scheduled task created, C2 connection to fake Microsoft security domain
      - **Capabilities Leveraged**: Keylogging captures passwords and email content, screen capture obtains network diagrams and confidential documents, file theft targets security policies and vendor contracts

10. **Long-Term Persistence & Ongoing Operations**  
    Maintain access for continuous intelligence collection:
      - **Persistence Mechanisms**:
        - **Edge Router ORB**: Rootkit-like hiding makes malware invisible, survives firmware upgrades, maintains redundant C2 channels
        - **Network Management Server**: Scheduled task persistence with 20-minute check-ins, SSH key backdoor provides permanent access, ongoing database connectivity
        - **Windows Workstation**: Registry persistence, domain admin credentials harvested for lateral movement
      - **Ongoing Intelligence Collection**:
        - Real-time CDR monitoring tracks government officials, military personnel, journalists
        - Email surveillance through ShadowPad monitors internal communications
        - Network configuration access provides immediate visibility into topology changes
        - VPN monitoring tracks government employees' remote access patterns
      - **Strategic Value**:
        - Mass surveillance capability across 15 million subscribers
        - Targeted monitoring with real-time tracking of individuals of interest
        - Complete visibility into telecommunications network architecture
        - Pre-positioned capabilities for potential future cyberwarfare scenarios
      - **Detection Status**: Campaign remains undetected with no EDR on Linux systems, automatic log cleaning, traffic blending with normal operations, and IT staff unaware of compromise
      - **Duration**: Multi-month persistence with ongoing intelligence collection operations


---

## Impact Assessment

=== "Confidentiality"
    Massive intelligence breach across telecommunications infrastructure:

    - **Call Detail Records (CDRs)**: Billions of records exposing who communicated with whom, when, duration (enables social network mapping, targeted surveillance)
    - **SMS Metadata**: Sender, recipient, timestamp for text messages (reveals communication patterns, relationships)
    - **Subscriber Data**: Personal information (names, addresses, national IDs, phone numbers) for millions of users
    - **Location Data**: Cell tower information in CDRs enables real-time tracking of individuals (precision: block-level in urban areas)
    - **VPN Logs**: Government employee remote access patterns (identifies officials, work schedules, accessed systems)
    - **Network Configurations**: Complete telecom infrastructure knowledge (router configs, BGP peers, VPN tunnels, security policies)
    - **Credentials**: SSH keys, passwords, API tokens for accessing critical infrastructure
    - **Mass Surveillance Capability**: Attacker gains nation-state-level visibility into entire country's telecommunications (equivalent to lawful intercept infrastructure)

=== "Integrity"
    Attacker has administrative control over critical telecom infrastructure:

    - **Traffic Manipulation**: Ability to modify routing tables (redirect traffic, man-in-the-middle attacks)
    - **Configuration Changes**: Alter firewall rules, disable security controls, weaken encryption
    - **Data Tampering**: Modify billing records, subscriber information, CDR databases (evidence destruction)
    - **Malware Injection**: Pre-position capabilities for future destructive attacks (ransomware, data wipers)
    - **Certificate Theft**: Stolen TLS certificates enable impersonation attacks (fake VPN servers, phishing)
    - **Supply Chain Risk**: Compromised telecom infrastructure can be leveraged to attack customers (ISP-level attacks)
    
    While UAT-7290's primary focus is espionage (not disruption), the access gained enables future integrity attacks if geopolitical situation escalates.

=== "Availability"
    Current campaign focused on stealth, but infrastructure compromise enables future disruption:

    - **Current Impact**:
      - Minimal service disruption (stealth operations maintain availability)
      - Slight performance degradation (malware consumes CPU/memory, bandwidth for exfiltration)
    
    - **Potential Future Impact**:

      - **Network Disruption**: Modify routing to black-hole traffic (internet outage)
      - **Service Degradation**: DDoS attacks launched from compromised infrastructure
      - **Ransomware Deployment**: Encrypt core systems (billing, CDR databases, network management)
      - **Cyberwarfare Scenario**: Pre-positioned capabilities for infrastructure destruction during geopolitical conflict
    
    UAT-7290's ORB infrastructure provides **persistent access for future operations**—availability risks increase if campaign transitions from espionage to disruption.

---

## Mitigation Strategies

### Patch Management

- **Prioritize Edge Device Patching**: Close initial access vectors:
  ```
  Critical Patching Strategy:
  
  1. Edge Networking Equipment:
     - Cisco routers/switches: Check for IOS/IOS XE security advisories
     - Fortinet firewalls: Subscribe to FortiGuard security alerts
     - Juniper devices: Monitor SIRT security advisories
     - Palo Alto Networks: Enable automatic security updates where feasible
  
  2. Patch Prioritization:
     - Critical/High severity: Patch within 72 hours (UAT-7290 exploits within days of disclosure)
     - Medium severity: Patch within 30 days
     - Proof-of-concept exploits published: Emergency patching (within 24 hours)
  
  3. Change Control Balance:
     - Risk of exploitation vs. risk of service disruption
     - For critical vulnerabilities: Accept service windows for emergency patching
     - Test patches on non-production systems when possible, but don't delay critical updates
  
  4. Out-of-Band Management:
     - Access management interfaces via dedicated management network (not internet-exposed)
     - VPN required for remote administration (no direct SSH/HTTPS from internet)
  ```

### Access Control Hardening

- **Eliminate Brute-Force Vectors**: Strengthen authentication:
  ```
  SSH Hardening (Linux/Unix Systems):
  
  1. Disable Password Authentication
  2. Implement Certificate-Based Authentication
  3. Multi-Factor Authentication for SSH
  4. IP Allowlisting
  5. Rate Limiting

  ```

- **Principle of Least Privilege**: Minimize admin access:
  ```
  Access Control Best Practices:
  
  1. Role-Based Access Control (RBAC):
     - Network engineers: Read-only access except during change windows
     - Security team: Monitoring access, no configuration changes
     - Contractors: Limited access, expire after project completion
  
  2. Just-In-Time (JIT) Administration:
     - No permanent admin accounts
     - Request elevated access for specific tasks (approved via workflow)
     - Access auto-revokes after time window (4 hours)
  
  3. Audit All Administrative Actions:
     - Enable audit logging on all systems
     - Log to centralized SIEM (cannot be tampered with on local system)
     - Alert on suspicious admin actions (off-hours access, config changes)
  ```

### Detection & Monitoring

- **Linux-Specific Threat Detection**: Deploy specialized tools:
  ```
  Linux EDR/XDR Solutions:
  - CrowdStrike Falcon for Linux
  - SentinelOne Singularity Linux
  - Trend Micro Deep Security (Linux support)
  - Wazuh (open-source HIDS for Linux)
  
  Configuration:
  1. File Integrity Monitoring (FIM):
     - Monitor critical directories: /usr/lib, /opt, /var, /etc
     - Alert on new hidden directories (starting with .)
     - Detect unauthorized binaries
  
  2. Process Monitoring:
     - Baseline normal processes
     - Alert on unusual process trees (bash spawning from network service)
     - Detect process hiding attempts (discrepancies between /proc and ps output)
  
  3. Network Connection Monitoring:
     - Log all outbound connections
     - Alert on connections to non-standard ports (not 80/443)
     - Detect DNS tunneling (excessive DNS queries, long TXT record responses)
  ```

- **SIEM Correlation Rules**: Detect UAT-7290 TTPs:
  ```
  SIEM Detection Rules (Splunk/Elastic/Sentinel):
  
  Rule 1: Hidden Directory Creation
  Rule 2: SSH Key Injection
  Rule 3: Unusual Cron Job Creation
  Rule 4: DNS Tunneling Detection
  Rule 5: Outbound Connection to ORB Indicators

  ```

### Network Segmentation

- **Isolate Management Networks**: Limit lateral movement:
  ```
  Network Segmentation Strategy:
  
  1. Dedicated Management VLAN:
     - Separate network for all device management interfaces
     - No routing to/from internet (air-gapped or via secured jumpbox)
     - Firewall rules: Block all traffic except from admin workstations
  
  2. Jumpbox/Bastion Host Architecture:
     - Single hardened Linux server for accessing management network
     - MFA required to access jumpbox
     - All admin sessions logged and recorded (screen recording)
  
  3. Zero Trust Architecture:
     - Never trust, always verify (even internal connections)
     - Require authentication for every system accessed
     - Micro-segmentation: Each critical system in own firewall zone
  ```

---

## Resources

!!! info "Cisco Talos Intelligence Report"
    - [China-Linked UAT-7290 Targets Telecoms with Linux Malware and ORB Nodes](https://thehackernews.com/2026/01/china-linked-uat-7290-targets-telecoms.html)
    - [Cisco Talos Intelligence Identifies China-Nexus Group UAT-7290 Targeting Telecom Infrastructure in South Asia](https://cybersecurityasia.net/uat-7290-cisco-identifies-china-nexus-group/)
    - [Cisco Talos uncovers UAT-7290 espionage campaign targeting critical infrastructure in South Asia - Industrial Cyber](https://industrialcyber.co/ransomware/cisco-talos-uncovers-uat-7290-espionage-campaign-targeting-critical-infrastructure-in-south-asia/)
    - [UAT-7290 Hackers Attacking Critical Infrastructure Entities in South Asia](https://cybersecuritynews.com/uat-7290-hackers-attacking-critical-infrastructure/)

---

*Last Updated: January 13, 2026*
