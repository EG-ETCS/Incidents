# China-Linked "Ink Dragon" APT Espionage Campaign

**APT Campaign**{.cve-chip} 
**China-Linked**{.cve-chip} 
**ShadowPad**{.cve-chip} 
**Government Targets**{.cve-chip}

## Overview

**Ink Dragon** is a **China-linked APT cluster** conducting **cyber espionage operations** across multiple continents in 2025, targeting **government and telecom networks** in Asia, South America, and Europe. The campaign leverages **misconfigured Microsoft IIS and SharePoint servers** as initial access vectors, exploiting **predictable ASP.NET machine keys** for **ViewState deserialization attacks** to achieve remote code execution. The threat actor deploys advanced malware including **ShadowPad backdoor** and **FINALDRAFT (Squidoor)** remote administration tools to maintain **stealthy long-term persistence**, exfiltrate sensitive data, and transform compromised systems into **C2 relay nodes**. The relay network architecture blends malicious traffic with legitimate communications, complicating detection and containment. The campaign demonstrates **sophisticated tradecraft** targeting governmental infrastructure with potential impact on **regional and global decision-making**.

---

## Campaign Specifications

| **Attribute**              | **Details**                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| **Threat Actor**           | Ink Dragon (China-Linked APT Cluster)                                      |
| **Campaign Timeline**      | Active and expanding in 2025                                               |
| **Target Sectors**         | Government, Telecommunications                                             |
| **Target Regions**         | Asia, South America, Europe, Africa                                        |
| **Initial Access Vector**  | Misconfigured Microsoft IIS and SharePoint servers                         |
| **Primary Exploit**        | ASP.NET ViewState Deserialization (predictable machine keys)               |
| **Malware Families**       | ShadowPad, FINALDRAFT (Squidoor), VARGEIT, NANOREMOTE                      |
| **Attack Objectives**      | Espionage, Data Exfiltration, Network Relay Establishment                  |
| **Persistence Mechanisms** | Scheduled tasks, Windows services, firewall rule modifications             |
| **Lateral Movement**       | Credential dumping (LSASS), registry hive extraction, privilege escalation |
| **C2 Architecture**        | Multi-hop relay network using compromised IIS servers                      |
| **Attribution Confidence** | Medium-High (China-linked based on malware, targets, and TTPs)             |
| **Detection Difficulty**   | High (stealthy implants, relay obfuscation, legitimate traffic blending)   |

---

## Technical Details

![](images/dragon1.png)

### Initial Access and Exploitation

Ink Dragon gains initial foothold through **exploitation of internet-facing web applications**:

- **Misconfigured IIS Servers**: Targets Microsoft Internet Information Services (IIS) servers with insecure configurations, weak authentication, or outdated security settings
- **SharePoint Vulnerabilities**: Exploits misconfigured or unpatched SharePoint installations exposed to internet
- **ASP.NET ViewState Deserialization**: Leverages **predictable or weak ASP.NET machine keys** to craft malicious ViewState payloads that trigger **deserialization vulnerabilities**, achieving **remote code execution** without authentication
- **Web Shell Deployment**: After initial exploitation, deploys ASP.NET web shells (ASPX files) for persistent command execution and file upload capabilities

### Malware Arsenal

#### ShadowPad Backdoor

**ShadowPad** is a modular **remote access trojan (RAT)** widely used by Chinese APT groups:

- **Modular Architecture**: Plugin-based framework allowing operators to load additional capabilities on demand (keylogging, screen capture, file operations)
- **Encrypted Communications**: Uses custom encryption protocols to hide C2 traffic from network inspection
- **IIS Listener Module**: Custom ShadowPad variant includes **IIS listener component** that embeds backdoor functionality into legitimate IIS processes, allowing compromised web servers to act as C2 relays
- **Stealth Techniques**: Process injection, DLL side-loading, and memory-only execution to evade endpoint detection

#### FINALDRAFT (Squidoor)

**FINALDRAFT** (also tracked as **Squidoor**) is an **advanced remote administration malware**:

- **Enhanced Stealth**: Designed for long-term persistence with minimal forensic footprint
- **Data Exfiltration**: Specialized modules for identifying, compressing, and exfiltrating sensitive documents and credentials
- **Network Reconnaissance**: Built-in capabilities for network mapping, asset discovery, and identification of high-value targets
- **Multi-Stage Deployment**: Typically deployed after initial ShadowPad infection, indicating escalation to high-priority targets

#### Supporting Tools

- **VARGEIT**: Component of toolkit, specific functionality not fully disclosed (likely credential harvesting or lateral movement module)
- **NANOREMOTE**: Lightweight remote access component, possibly used for initial reconnaissance or low-footprint persistence

### Relay Network Architecture

Ink Dragon's **most distinctive capability** is the establishment of **C2 relay networks**:

- **Compromised IIS Servers as Relays**: Infected web servers configured to forward C2 commands between attacker infrastructure and deeper network targets
- **Traffic Blending**: Relay nodes mix malicious C2 traffic with legitimate HTTP/HTTPS web traffic, making network-based detection extremely difficult
- **Multi-Hop Communication**: Commands routed through multiple compromised hosts before reaching final target, complicating attribution and takedown
- **Resilient Infrastructure**: Loss of individual relay nodes doesn't disrupt entire operation; network can dynamically reconfigure

### Credential Harvesting and Privilege Escalation

- **LSASS Memory Dumps**: Extracts credentials from Local Security Authority Subsystem Service (LSASS) process memory using tools like ProcDump or custom dumpers
- **Registry Hive Extraction**: Copies SAM, SECURITY, and SYSTEM registry hives for offline password hash cracking
- **Pass-the-Hash Attacks**: Uses harvested NTLM hashes for lateral movement without needing plaintext passwords
- **Domain Enumeration**: Active Directory reconnaissance to identify privileged accounts, domain controllers, and critical servers

### Persistence and Defense Evasion

- **Scheduled Tasks**: Creates tasks that periodically execute malware loaders, often disguised with legitimate-sounding names
- **Windows Services**: Installs malware as system services for automatic startup and SYSTEM-level privileges
- **Firewall Rule Modification**: Adds permissive outbound firewall rules to allow C2 communications and data exfiltration
- **Legitimate Tool Abuse**: Uses built-in Windows utilities (PowerShell, WMI, WMIC, net commands) to minimize custom tooling and evade behavioral detection

---

## Attack Scenario

### Step-by-Step Campaign Execution

1. **External Reconnaissance**  
   Ink Dragon conducts **internet-wide scanning** for exposed Microsoft IIS and SharePoint servers. Identifies misconfigured instances with **predictable ASP.NET machine keys** or known vulnerabilities. Uses tools like Shodan, Censys, and custom scanners to enumerate targets in government and telecom sectors across Asia, South America, and Europe.

2. **Initial Exploitation — ViewState Deserialization**  
   Attackers craft malicious **ASP.NET ViewState payloads** exploiting predictable machine keys. Sends crafted HTTP requests triggering **deserialization vulnerability**, achieving **remote code execution** on IIS/SharePoint server. No authentication required. Executes commands with IIS application pool privileges.

3. **Web Shell Deployment**  
   Uploads **ASPX web shell** to compromised server for persistent command execution. Web shell typically disguised as legitimate file (e.g., `error.aspx`, `upload.aspx`) in rarely-monitored directories. Provides file upload, command execution, and network pivoting capabilities.

4. **Malware Installation — ShadowPad and FINALDRAFT**  
   Deploys **ShadowPad backdoor** via web shell or staged loader. Installs **IIS listener module** to convert server into C2 relay node. For high-value targets, deploys **FINALDRAFT** for advanced exfiltration and reconnaissance. Additional components (VARGEIT, NANOREMOTE) installed based on operational requirements.

5. **Credential Harvesting and Privilege Escalation**  
   Dumps **LSASS process memory** to extract plaintext passwords, NTLM hashes, and Kerberos tickets. Copies registry hives (SAM, SECURITY, SYSTEM) for offline analysis. Uses harvested credentials for **lateral movement** to domain controllers, file servers, and workstations. Escalates to **domain administrator** privileges.

6. **Persistence Establishment**  
   Creates **scheduled tasks** for periodic malware execution. Installs malware as **Windows services** with automatic startup. Modifies **Windows Firewall rules** to allow broad outbound connectivity. Deploys multiple persistence mechanisms to survive reboots and detection attempts.

7. **Relay Network Configuration**  
   Configures compromised IIS servers as **C2 relay nodes** using ShadowPad IIS listener. Relay nodes forward commands between attacker-controlled infrastructure and internal targets. Malicious traffic **blends with legitimate HTTP/HTTPS traffic**, evading network monitoring. Multi-hop architecture provides **operational resilience** and **attribution complexity**.

8. **Data Exfiltration and Long-Term Espionage**  
   Identifies and exfiltrates **sensitive government documents**, diplomatic communications, operational data, and network architecture information. Maintains **stealthy long-term presence** for ongoing intelligence collection. Monitors victim communications, policy discussions, and strategic decision-making processes.

---

## Impact Assessment

=== "Government Impact"
    * Compromise of **government networks** in multiple countries provides China-linked actors with **strategic intelligence** on policy decisions, diplomatic strategies, and regional negotiations. 
    * Access to **sensitive communications** enables anticipation of government positions, potential blackmail opportunities, and **influence operations**. 
    * Long-term persistence allows real-time monitoring of evolving political situations. 
    * Impact extends beyond data theft to potential **disruption of democratic processes** and **national sovereignty violations**.

=== "Telecommunications Impact"
    * Targeting of **telecom networks** provides access to **communications metadata and content** for surveillance of specific individuals, organizations, or government officials. 
    * Compromised telecom infrastructure enables **interception of calls, SMS, and data traffic**. 
    * Attackers can identify targets' locations, communication patterns, and social networks. 
    * Access to telecom routing and signaling systems could enable **traffic manipulation** or **service disruption**.

=== "Operational Security Impact"
    * **Relay network architecture** makes detection and remediation extremely challenging. 
    * Compromised systems continue forwarding traffic even after apparent cleanup, requiring **comprehensive network-wide investigation**. 
    * Credential theft enables **persistent re-entry** even after malware removal. 
    * Organizations face **extended incident response timelines** and uncertainty about full scope of compromise. 
    * False sense of security after partial remediation allows attackers to maintain access.

=== "Regional Stability Impact"  
    * Multi-continent targeting (Asia, South America, Europe) suggests **coordinated intelligence collection** supporting China's geopolitical objectives. 
    * Compromised governmental infrastructure could influence **international negotiations**, **trade agreements**, and **security partnerships**. 
    * Intelligence collected may support **economic espionage**, **intellectual property theft**, or **diplomatic coercion**. 
    * Revelation of extensive compromise could **damage international trust** and **strain diplomatic relations**.

---

## Mitigation Strategies

### Preventive Actions

- **IIS and SharePoint Hardening**: Remove unnecessary features, disable directory browsing, implement principle of least privilege for application pools. Restrict administrative access to trusted IPs only.
- **Machine Key Rotation**: **Regenerate ASP.NET machine keys** with cryptographically strong random values. Configure unique keys per application. Store keys securely outside web directories. Rotate keys regularly.
- **Security Patching**: Maintain current patch levels for Windows Server, IIS, SharePoint, and .NET Framework. Subscribe to Microsoft security advisories. Implement automated patch management where feasible.
- **Network Segmentation**: Isolate internet-facing web servers in DMZ with strict firewall rules. Prevent direct communication between DMZ and internal corporate network. Require proxy or jump host for any DMZ-to-internal access.
- **Input Validation**: Implement strict input validation for all web applications. Disable ViewState where not required. Enable ViewState MAC (Message Authentication Code) validation.

### Detection and Monitoring

- **EDR Deployment**: Deploy **Endpoint Detection and Response (EDR)** solutions across all servers and workstations. Configure behavioral analytics to detect LSASS dumping, suspicious scheduled tasks, and unusual outbound connections.
- **Network Traffic Analysis**: Monitor for **unusual HTTP/HTTPS patterns** from IIS servers, especially to unexpected external IPs. Detect multi-hop traffic patterns indicating relay behavior. Analyze SSL/TLS certificate anomalies.
- **Web Server Integrity Monitoring**: Implement **file integrity monitoring (FIM)** for IIS and SharePoint directories. Alert on creation of new ASPX files, DLL modifications, or IIS configuration changes. Review IIS logs for anomalous requests.
- **Credential Monitoring**: Deploy honeypot accounts and **monitor for unauthorized access attempts**. Alert on privilege escalation events. Track usage of administrative credentials across network.
- **Scheduled Task Auditing**: Monitor creation of new scheduled tasks. Investigate tasks with suspicious names, unusual execution times, or references to temporary directories. Correlate with user authentication logs.

### Threat Hunting

- **ShadowPad Indicators**: Hunt for ShadowPad artifacts: encrypted configuration files, characteristic DLL names, registry keys, and network beaconing patterns documented in threat intelligence reports.
- **FINALDRAFT Signatures**: Search for FINALDRAFT file hashes, mutex names, and command-and-control patterns. Review archives and staging directories for exfiltration preparation.
- **Relay Node Identification**: Analyze IIS servers forwarding traffic to unusual destinations. Identify systems acting as proxy or relay without legitimate business justification. Investigate systems with both inbound and outbound connections to external IPs.
- **Registry and LSASS Dumps**: Hunt for ProcDump usage, registry hive copies in unusual locations (TEMP, user directories), or SAM database exports. Investigate unexplained memory dumps.

### Incident Response

- **System Isolation**: Immediately isolate suspected compromised hosts from network. Maintain forensic copies of volatile memory and disk for investigation. Do not immediately reboot (destroys memory evidence).
- **Credential Reset**: Force password reset for **all user accounts** in affected domains, prioritizing administrative and service accounts. Invalidate cached credentials and Kerberos tickets. Assume all credentials harvested.
- **Relay Node Elimination**: Identify and remediate all relay nodes in network. Removing only directly-compromised systems insufficient; attackers maintain access through relay infrastructure. Network-wide investigation required.
- **Malware Removal**: Use known indicators of compromise (IOCs) to search for and remove ShadowPad, FINALDRAFT, and associated tools across entire environment. Rebuild critical systems from known-clean media.
- **Firewall Rule Review**: Audit all firewall rules, especially outbound rules. Remove any permissive rules added by attackers. Implement default-deny egress policy with explicit allows for required services.

### Long-Term Hardening

- **Zero Trust Architecture**: Implement zero trust principles requiring authentication and authorization for all network communications, even between internal systems. Eliminate implicit trust based on network location.
- **Privileged Access Workstations (PAWs)**: Restrict administrative access to hardened workstations used solely for administration. Prevent privileged credential use on general-purpose systems.
- **Multi-Factor Authentication**: Enforce MFA for all administrative access, VPN connections, and access to sensitive systems. Use phishing-resistant MFA (FIDO2, smart cards) where possible.
- **Regular Security Audits**: Conduct periodic penetration testing and red team exercises specifically testing for IIS/SharePoint misconfigurations and credential harvesting resilience.

---

## Resources

!!! info "Threat Intelligence Reports"
    - [Chinese-based Ink Dragon Compromises Asia and South America into European](https://teamwin.in/chinese-based-ink-dragon-compromises-asia-and-south-america-into-european-government-networks/)
    - [China-Linked Ink Dragon Hacks Governments Using ShadowPad and FINALDRAFT Malware](https://thehackernews.com/2025/12/china-linked-ink-dragon-hacks.html)
    - [Experts Warn Chinese "Ink Dragon" Hackers Extend Reach into European Governments — TechRadar](https://www.techradar.com/pro/security/experts-warn-chinese-ink-dragon-hackers-extend-reach-into-european-governments)
    - [Ink Dragon's Relay Network and Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

---
