# DynoWiper Cyberattack on Polish Energy Systems (Sandworm Attribution)
![alt text](images/dynowiper.png)

## Overview

In late 2025, Polish energy infrastructure became the target of a sophisticated destructive cyberattack attributed to **Sandworm** (also tracked as APT44, Voodoo Bear, or IRIDIUM), a Russian military intelligence-aligned threat actor operating under the GRU's Unit 74455. The attackers deployed a newly identified wiper malware dubbed **DynoWiper**, designed to irreversibly delete critical data and render operational technology (OT) systems inoperable. The operation aimed to disrupt electricity and heating services to potentially 500,000+ residents during winter months, representing a significant escalation in state-sponsored cyber warfare targeting European critical infrastructure.

Despite achieving initial access and lateral movement within targeted energy networks, the attack was ultimately **unsuccessful**. Polish cybersecurity authorities, working in coordination with CERT Polska and energy sector partners, detected the intrusion before DynoWiper could execute its destructive payload on critical industrial control systems (ICS). The incident triggered immediate legislative action, with Poland introducing stricter cybersecurity regulations for critical infrastructure operators and establishing enhanced IT/OT security requirements modeled after the EU's NIS2 Directive.

The attack demonstrates Sandworm's continued focus on energy infrastructure disruption following their notorious campaigns against Ukraine's power grid (2015, 2016) and highlights the persistent threat of Russian state-sponsored cyber operations against NATO member states and European Union critical infrastructure.

---

## Incident Specifications

| **Attribute**              | **Details**                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| **Malware Name**           | DynoWiper                                                                   |
| **Detection Signature**    | Win32/KillFiles.NMO (ESET), ESET-NOD32: A Variant Of Win32/KillFiles.NMO   |
| **SHA-1 Hash**             | `4EC3C90846AF6B79EE1A5188EEFA3FD21F6D4CF6`                                  |
| **Threat Actor**           | Sandworm (APT44, Voodoo Bear, IRIDIUM) - GRU Unit 74455                    |
| **Target Sector**          | Energy / Critical Infrastructure                                            |
| **Target Geography**       | Poland (NATO/EU Member State)                                               |
| **Attack Timeframe**       | Late 2025 (December suspected based on winter heating disruption goal)      |
| **Attack Outcome**         | Unsuccessful - Detected and contained before operational impact             |
| **Potential Impact**       | Estimated 500,000+ residents (electricity/heating disruption)               |
| **Malware Category**       | Destructive Wiper                                                           |

---

## Technical Details

### DynoWiper Malware Analysis

**DynoWiper** is a destructive wiper malware specifically engineered for data destruction and system disruption in industrial environments. Unlike ransomware that encrypts data for financial extortion, wipers like DynoWiper are designed for **pure destruction** with no recovery mechanism, making them weapons of cyberwarfare rather than cybercrime.

#### Malware Behavior Profile

DynoWiper operates through a four-stage execution process:

1. **Initial Execution** - The malware gains execution privileges and disables security mechanisms including antivirus, endpoint detection and response (EDR) tools, and system logging to avoid detection.

2. **Filesystem Enumeration** - DynoWiper systematically identifies critical system directories, operational technology and industrial control system (OT/ICS) configuration files, and backup recovery systems across the target environment.

3. **Data Destruction Phase** - The malware overwrites files with random data, deletes system recovery partitions, corrupts boot sectors and Master Boot Records (MBR), and destroys OT historian databases that store critical operational history.

4. **System Disruption** - Finally, DynoWiper terminates critical processes, removes shadow copies and backup systems, and forces system shutdowns or reboot loops to render systems inoperable.

#### Detection Signature Analysis

**ESET Detection:** `Win32/KillFiles.NMO`

The "KillFiles" designation indicates aggressive file destruction behavior characteristic of wiper malware. The ".NMO" variant suffix suggests a new evolution of previously observed wiper families. The malware's SHA-1 hash (`4EC3C90846AF6B79EE1A5188EEFA3FD21F6D4CF6`) enables detection across enterprise systems.

#### Sandworm Attribution Indicators

Attribution to Sandworm is based on multiple overlapping indicators:

- **Target Profile:** Energy infrastructure targeting consistent with Sandworm's 2015/2016 Ukraine power grid attacks and 2022 Industroyer2 operations
- **Destructive Intent:** Pure wiper deployment without ransom demands, which is Sandworm's operational signature
- **Geopolitical Context:** Poland as a NATO and EU member state supporting Ukraine during the ongoing conflict
- **Tactical Overlap:** Similar lateral movement and ICS targeting patterns observed in previous Sandworm campaigns
- **Timing:** Late 2025 attack during winter heating season mirrors Sandworm's December 2015 Ukraine attack
- **ESET Analysis:** ESET researchers linked DynoWiper to Sandworm operations based on similarities to NotPetya and Industroyer2 malware families


---

## Attack Scenario: Polish National Energy Operator Breach

**Target Organization:** Polskie Sieci Energetyczne S.A. (PSE) - Poland's transmission system operator

**Threat Actor:** Sandworm (GRU Unit 74455)

**Attack Vector:** Supply chain compromise via third-party OT vendor

### Initial Access & Reconnaissance

Sandworm gained initial access to PSE's corporate network through a compromised software update from **EnergoTech Solutions**, a Polish OT vendor providing SCADA monitoring software to European energy operators. The attackers breached the vendor's build environment and injected a trojanized version of their monitoring software distributed to PSE.

The malicious update contained a stealthy backdoor providing remote access while maintaining legitimate functionality to avoid detection. Initial reconnaissance identified:

- Corporate IT workstations and business systems
- OT systems including SCADA servers and HMI workstations
- Multiple substations with remote terminal units managing transmission
- Control centers coordinating electricity distribution
- Poor IT/OT network segmentation with shared directory services

### Lateral Movement & Privilege Escalation

Using stolen credentials harvested from the IT network, Sandworm operators moved laterally into PSE's OT environment. The attackers:

- Compromised privileged administrative accounts through credential attacks
- Established persistence on multiple SCADA servers
- Deployed reconnaissance tools to map substation configurations
- Staged DynoWiper malware across substation gateways and control center servers
- Configured synchronized execution across all compromised OT systems

### Detection & Emergency Response

PSE's Security Operations Center detected anomalous lateral movement patterns during routine network monitoring. Security teams identified the malicious software update as the intrusion vector and discovered DynoWiper binaries staged on OT systems.

Emergency coordination activated with Poland's national CERT, Internal Security Agency, Ministry of Climate, and NATO partners. Response actions included:

- Immediate isolation of all compromised OT systems
- Removal of DynoWiper binaries from affected systems
- Emergency patching of the compromised software
- Complete IT/OT network segmentation with emergency firewall rules
- Forensic imaging and analysis of OT systems
- Systems restored and brought back online under enhanced monitoring

The attack was successfully **contained** with zero operational impact on electricity transmission or distribution.

### Attribution & Disclosure

Security researchers linked DynoWiper to Sandworm based on code similarities to previous malware families and overlap with known threat actor tactics. Polish government publicly attributed the attack to Russian military intelligence, with confirmation from independent analysis and international partners.

---

## Impact Assessment

=== "Operational Impact"

    **Actual Disruption: None**

    - No confirmed power outages or energy disruptions
    - All electricity and heating services maintained uninterrupted
    - Attack detected and contained before operational systems were affected

=== "Potential Impact & Security Implications"

    **Had the Attack Succeeded:**

    - Estimated 500,000+ residents could have been affected by energy and heating supply disruptions
    - Complete blackout of transmission systems through OT network destruction
    - Extended recovery period due to wiper damage to industrial control systems and backups
    - Significant public health and safety risks during winter months

    **Security Impact:**

    - Elevated concerns about state-sponsored cyber threats to critical infrastructure
    - Demonstrated vulnerability of energy sector to supply chain compromise vectors
    - Highlighted risks of inadequate IT/OT segmentation in European energy operators
    - Confirmed Sandworm's capability and intent to target NATO member infrastructure

=== "Compliance & Political Impact"

    **Political & Legislative Response:**

    - Increased urgency for stronger national cybersecurity legislation
    - Accelerated protections for IT/OT environments across European critical infrastructure
    - Enhanced NATO coordination on cyber defense against Russian state actors
    - EU sanctions discussions targeting Russian military cyber operations


## Mitigation Strategies

### Immediate Actions

**Emergency Response - Critical Infrastructure Operators**

**Step 1: Threat Hunting for DynoWiper Indicators**

- Search all systems for DynoWiper malware using SHA-1 hash: `4EC3C90846AF6B79EE1A5188EEFA3FD21F6D4CF6`
- Immediately quarantine any detected files
- Review scheduled tasks for suspicious entries created within the last 7 days
- Analyze authentication logs for unauthorized lateral movement (network and remote logons)
- Notify CERT immediately if malware is discovered

**Step 2: Emergency IT/OT Network Segmentation**

- Block all traffic from IT network to OT network by default
- Allow access only through authorized jump servers with multi-factor authentication
- Log and alert on any OT-to-Internet connections
- Implement this segmentation at firewall boundaries

**Step 3: Disable Risky Protocols in OT Environment**

- Disable SMBv1; restrict SMBv2/v3 to authorized file servers only
- Enforce RDP access exclusively through secure jump servers with MFA
- Disable Telnet, FTP, and Windows Remote Registry services
- Disable PowerShell Remoting unless explicitly required

**Step 4: Backup Validation & Offline Storage**

- Verify integrity of all OT system backups through test restoration on isolated systems
- Ensure backups are air-gapped or stored offline to prevent wiper attacks
- Implement immutable backup storage for critical SCADA configurations
- Test full recovery procedures to confirm rebuilding capability within 24 hours

### Long-Term Security Hardening

**1. OT Security Architecture Redesign**

Implement ISA/IEC 62443 security zones with proper segmentation:

- Separate operations management (Level 3) from SCADA systems (Level 2) from field devices (Level 1)
- Deploy ICS-aware firewalls between zones with protocol filtering
- Restrict cross-zone communication to authorized pathways only
- Use unidirectional gateways for data flows where possible

**2. Vendor Security Requirements**

Mandate security controls from all OT software and hardware vendors:

- Secure software development lifecycle with code signing and third-party audits
- Coordinated vulnerability disclosure with 90-day remediation timelines
- Cryptographically signed updates with rollback capabilities
- Annual independent penetration testing
- 24/7 security contact for critical vulnerabilities

**3. Threat Detection & Response**

Deploy OT-specific monitoring capabilities:

- Install OT endpoint detection and response (EDR) tools on SCADA and HMI systems
- Implement passive network traffic analysis for anomaly detection
- Establish baseline profiles of normal OT operations
- Subscribe to ICS-CERT advisories, CISA alerts, and vendor threat feeds
- Develop incident response playbooks for wiper attacks and insider threats

**4. Security Awareness & Training**

Establish comprehensive training program:

- All OT engineers must complete ICS cybersecurity certification
- Quarterly phishing awareness simulations for IT and OT staff
- Insider threat recognition training
- Annual tabletop exercises simulating nation-state attacks

**5. Regulatory Compliance**

Align operations with industry standards:

- EU NIS2 Directive requirements for cybersecurity risk management
- IEC 62443 industrial automation security standards
- ISO 27001 and ISO 27019 information security frameworks
- NERC CIP standards (if applicable for North American operations)


---

## Resources

!!! info "News Coverage"
    - [Sandworm hackers linked to failed wiper attack on Poland’s energy systems](https://www.bleepingcomputer.com/news/security/sandworm-hackers-linked-to-failed-wiper-attack-on-polands-energy-systems/)
    - [New DynoWiper Malware Used in Attempted Sandworm Attack on Polish Power Sector](https://thehackernews.com/2026/01/new-dynowiper-malware-used-in-attempted.html)
    - [Russian military intelligence hackers likely behind December cyberattacks on Polish energy targets, researchers say | Reuters](https://www.reuters.com/technology/russian-military-intelligence-hackers-likely-behind-december-cyberattacks-polish-2026-01-23/)
    - [ESET Research: Sandworm behind cyberattack on Poland’s power grid in late 2025](https://www.welivesecurity.com/en/eset-research/eset-research-sandworm-cyberattack-poland-power-grid-late-2025/)
    - [Wiper malware targeted Poland energy grid, but failed to knock out electricity - Ars Technica](https://arstechnica.com/security/2026/01/wiper-malware-targeted-poland-energy-grid-but-failed-to-knock-out-electricity/)

---

*Last Updated: January 25, 2026* 
