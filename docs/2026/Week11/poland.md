# Cyberattack Targeting the National Centre for Nuclear Research (NCBJ)
![alt text](images/poland.png)

**Critical Infrastructure**{.cve-chip} **Nuclear Sector**{.cve-chip} **Cyberattack**{.cve-chip}

## Overview

Polish authorities detected and blocked a cyberattack targeting the IT infrastructure of the National Centre for Nuclear Research (NCBJ). The intrusion attempt aimed to access internal systems, but security monitoring identified suspicious activity early and defenders contained the threat before operational systems were affected.

Initial investigation suggested possible links to infrastructure associated with actors in Iran. Attribution remains unconfirmed and investigators noted that false-flag techniques are possible.

## Technical Specifications

| Field | Details |
|-------|---------|
| **Incident Type** | Targeted cyberattack / unauthorized access attempt |
| **Primary Target** | National Centre for Nuclear Research (NCBJ), Poland |
| **Target Environment** | IT infrastructure and internal networks |
| **Detection Method** | Security monitoring, unauthorized access alerts, abnormal network activity |
| **Operational Impact** | No disruption to reactor or nuclear research operations |
| **Attribution Status** | Under investigation; possible Iran-linked infrastructure noted |

## Affected Products

- NCBJ internal IT systems and network segments.
- No reported compromise of industrial control systems (ICS) or reactor control systems.
- MARIA research reactor operations remained normal.

## Technical Details

- Attack activity focused on IT infrastructure and internal networks of the research center.
- Security systems detected unauthorized access attempts and anomalous network behavior.
- No compromise of ICS or reactor control systems was reported.
- Indicators of compromise suggested potential links to infrastructure previously associated with Iran-linked actors, though attribution is still pending.
- Incident response teams isolated affected systems and started forensic analysis.

## Attack Scenario

1. Threat actors attempted to gain access to the research center's IT environment.
2. The intrusion likely involved reconnaissance and/or credential-based access attempts.
3. Monitoring controls detected suspicious behavior and unauthorized access attempts.
4. The organization activated incident response procedures.
5. Security teams isolated systems and blocked the intrusion before lateral movement or access to sensitive assets.

## Impact Assessment

=== "Operational Impact"
    No disruption to nuclear research operations was reported.

=== "Safety Impact"
    No evidence indicated compromise of reactor systems or safety-related controls.

=== "Strategic Impact"
    No reported data exfiltration was disclosed, and the incident triggered a national cybersecurity investigation with elevated monitoring of critical infrastructure.

## Mitigation Strategies

- Maintain layered network monitoring and intrusion detection systems.
- Execute rapid incident response playbooks, including containment and system isolation.
- Coordinate with national cybersecurity authorities for investigation and threat intelligence sharing.
- Apply continuous monitoring of critical infrastructure networks.
- Strengthen authentication controls and enforce segmentation between IT and operational technology (OT) environments.

## Resources

!!! info "Open-Source Reporting"
    - [Hackers targeted Poland's National Centre for Nuclear Research](https://securityaffairs.com/189399/security/hackers-targeted-polands-national-centre-for-nuclear-research.html)
    - [Poland says foiled cyberattack on nuclear centre may have come from Iran | Reuters](https://www.reuters.com/world/poland-says-foiled-cyberattack-nuclear-centre-may-have-come-iran-2026-03-12/)
    - [Poland's nuclear research centre targeted by cyberattack](https://www.bleepingcomputer.com/news/security/polands-nuclear-research-centre-targeted-by-cyberattack/)
    - [Nuclear Facility Cyberattack Investigated as Possible Iranian Exploit | Security Magazine](https://www.securitymagazine.com/articles/102170-nuclear-facility-cyberattack-investigated-as-possible-iranian-exploit)
    - [Poland says Iran may be behind foiled cyberattack on nuclear center | Iran International](https://www.iranintl.com/en/202603127684)

---
*Last Updated: March 15, 2026*