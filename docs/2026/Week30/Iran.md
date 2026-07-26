# Iran-Linked Threat Actors Target U.S. Water and Energy Control Systems
![alt text](images/Iran.png)

**Iran-Linked APT Activity**{.cve-chip} **ICS/OT Targeting**{.cve-chip} **SCADA/PLC Manipulation**{.cve-chip} **Critical Infrastructure Risk**{.cve-chip} **Operational Disruption**{.cve-chip}

## Overview

Iran-linked advanced threat actors are actively targeting U.S. critical infrastructure operational technology environments, particularly water and energy control systems.

The campaign centers on gaining access to exposed industrial assets and manipulating process logic, alarms, and operator visibility to disrupt physical operations rather than conduct only traditional cyber espionage.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Threat Focus** | U.S. water and energy ICS/OT environments |
| **Primary Targets** | Internet-exposed PLCs, HMIs, SCADA servers, engineering workstations |
| **Likely Initial Access Methods** | Default credentials, weak passwords, exposed remote access, known vulnerabilities |
| **Post-Access Activity** | Asset discovery, configuration/logic collection, process manipulation |
| **Manipulation Behavior** | PLC logic changes, parameter modification, alarm suppression, HMI display tampering |
| **Persistence Objective** | Maintain remote operational access for ongoing interference |
| **Disclosed CVEs/Malware** | Not publicly enumerated in advisory context |
| **Potential Consequence Domain** | Physical process disruption and safety impact |

## Affected Products

- Internet-reachable PLCs and industrial controllers
- HMIs and SCADA management servers with weak access controls
- Engineering workstations used for PLC project deployment and process tuning
- OT environments lacking robust IT/OT segmentation and monitoring

## Attack Scenario

1. Threat actors scan externally reachable OT assets across water and energy operators.
2. Weak authentication and exposed management paths are exploited for initial access.
3. Attackers enumerate OT components and collect PLC project/configuration data.
4. Control logic and process parameters are modified, while operator visibility is degraded via HMI/alarm manipulation.
5. Disruption follows through process instability, delayed operator response, and potential equipment/safety impact.

## Impact Assessment

=== "Integrity"

    - Unauthorized modification of PLC logic and operating parameters can alter physical process behavior
    - HMI tampering and alarm suppression undermine trust in operator decision support
    - Process-control integrity degradation may enable repeat manipulation after initial incident

=== "Confidentiality"

    - Exposure of industrial configurations and process engineering data
    - Leakage of operational design details that can support future attacks
    - Increased intelligence value for adversaries targeting sector-wide infrastructure

=== "Availability"

    - Water treatment and wastewater process interruption risk
    - Energy distribution/operations disruption and possible equipment downtime
    - Extended service recovery windows due to OT validation and safety requalification

## Mitigation Strategies

### Immediate Actions

- Remove OT assets from direct internet exposure wherever possible
- Replace default credentials with strong, unique credentials on all ICS management interfaces
- Disable unnecessary remote access paths and unused services

### Short-term Measures

- Enforce strict IT/OT segmentation and isolate control systems from enterprise/user networks
- Apply available firmware/software patches for known vulnerabilities in OT components
- Restrict remote management with MFA and tightly scoped allowlisted access

### Monitoring & Detection

- Continuously monitor PLC logic/configuration changes and alert on unauthorized modifications
- Deploy OT-aware network monitoring for anomalous command and protocol behavior
- Audit HMI/alarm configuration integrity and track unexpected suppression events

### Long-term Solutions

- Maintain tested offline backups of PLC programs and engineering projects
- Build OT incident response playbooks that include safe process restoration procedures
- Conduct recurring security assessments of exposed industrial assets and remote-access architecture

## Resources and References

!!! info "Public Reporting"
    - [Iran-Linked Actors Are Targeting US Water and Energy Control Systems](https://securityaffairs.com/195991/apt/iran-linked-actors-breach-are-targeting-us-water-and-energy-control-systems.html)
    - [Iranian-Affiliated Cyber Actors Exploit Programmable Logic Controllers Across US Critical Infrastructure | CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a)

---

*Last Updated: July 26, 2026*
