# Cyberattacks on Poland's Water Plants: A Blueprint for Hybrid Warfare
![alt text](images/Blueprint.png)

**OT/ICS Security**{.cve-chip} **APT28**{.cve-chip} **APT29**{.cve-chip} **UNC1151**{.cve-chip} **Hybrid Warfare**{.cve-chip} **Critical Infrastructure**{.cve-chip}

## Overview

Poland's Internal Security Agency (ABW) revealed that state-linked Russian and Belarusian APT groups breached industrial control systems at five Polish water treatment plants during 2025, gaining the ability to alter operational parameters of pumps, filters, and chemical dosing equipment in real time. The campaign exploited basic security failures — default credentials and internet-exposed OT interfaces — rather than zero-day vulnerabilities, making it a highly replicable blueprint for hybrid warfare against water infrastructure globally.

The attacks are attributed to APT28 (Fancy Bear), APT29 (Cozy Bear), and UNC1151 (Belarus-aligned, associated with Ghostwriter operations). ABW explicitly described one attack as potentially capable of cutting off a city's water supply. The same reporting period also covered a Sandworm-attributed attack on a Polish combined heat-and-power plant in December 2025, underscoring the breadth of the hybrid campaign.

!!! note "No CVE — Configuration and Credential Failures"
    No advanced vulnerabilities or zero-days were used. Attackers exploited default and weak passwords on ICS/SCADA systems and management interfaces exposed directly to the internet — failures of basic operational security hygiene.

## Technical Specifications

| Attribute | Details |
|---|---|
| **Targeted Sites** | Jabłonna Lacka, Szczytno, Małdyty, Tolkmicko, Sierakowo (five municipal water treatment plants) |
| **Attack Vectors** | Default/weak passwords; internet-exposed OT management interfaces |
| **Systems Accessed** | ICS/SCADA systems controlling pumps, filters, flushing cycles, chemical dosing |
| **Capabilities Obtained** | Real-time modification of device operating parameters |
| **Attribution** | APT28, APT29 (Russia); UNC1151 (Belarus / Ghostwriter) |
| **Related Actor** | Sandworm (December 2025 heat-and-power plant attack) |
| **CVE** | None — exploitation of misconfiguration and default credentials |
| **Incident Period** | Throughout 2025 |
| **Geopolitical Context** | Attacks intensified following Poland's pro-Ukraine government election and its role as a NATO logistics hub |

## Affected Products

- **ICS/SCADA systems and HMI interfaces** at Polish municipal water treatment plants
- **PLC gateways and remote-access appliances** in water-sector OT networks with internet-facing management interfaces
- Any water utility globally with similar misconfigurations — ABW and analysts explicitly note the blueprint applies to U.S. and other countries' water infrastructure

## Attack Scenario

1. **Reconnaissance and target selection** — APT actors scan for internet-exposed water-sector OT assets (SCADA/HMI interfaces, PLC gateways, remote-access appliances) in Polish municipalities; five plants are identified with open management interfaces and default or weak credentials
2. **Initial access via default credentials** — attackers log directly into ICS/SCADA interfaces or remote-access tools over the internet using default or trivial passwords; no advanced exploit is required
3. **ICS compromise at Szczytno (May 2025)** — attackers access supervisory control systems and change flushing cycles while operators watch the changes occur in real time on a live feed
4. **ICS manipulation at Jabłonna Lacka (September 2025)** — video evidence shows an intruder logged in via an admin account altering pump and filter threshold settings, with direct ability to affect water quality and continuity parameters
5. **Operational risk assessment** — ABW determines that one attack could have caused a city to lose its water supply before it was thwarted; the operations are characterized as tests of sabotage options and resilience rather than immediate mass-casualty attempts
6. **Hybrid warfare integration** — intrusions are coordinated with disinformation and information-warfare operations (UNC1151 / Ghostwriter), creating sustained psychological and operational pressure on Polish infrastructure and political stability

## Impact

=== "Direct Operational Risk"

    - Attackers achieved hands-on-keyboard control of water ICS with the ability to disrupt water pressure and flow, interfere with filtration and flushing processes, and potentially affect chemical dosing and quality parameters
    - ABW explicitly describes a "direct threat to continuity of water supply processes and proper functioning of municipal infrastructure"
    - One attack was assessed as capable of cutting off a city's water supply before it was detected and thwarted

=== "Public Health and Safety"

    - While no confirmed water contamination or mass outage occurred, intrusion into drinking-water infrastructure creates risk of water-quality incidents with health consequences if chemicals or filtration are misconfigured
    - Water outages impact hygiene, healthcare, and industrial operations in affected municipalities
    - The demonstrated capability — not just access but parameter modification — represents a significant escalation of risk for civilian populations

=== "Strategic and Geopolitical Impact"

    - Supports a documented hybrid warfare campaign by Russia and Belarus targeting Poland as a front-line NATO/EU state and primary logistics hub for Ukraine aid
    - Demonstrates that OT attacks have expanded beyond energy grids to local municipal water and heating infrastructure, complicating NATO and EU deterrence
    - ABW and security analysts assess that the same attack blueprint — default credentials, internet-exposed OT — is replicable against water utilities in the United States and across Europe with minimal technical sophistication, making this a globally relevant warning

## Mitigations

### Eliminate Internet Exposure of OT Systems

- **Remove direct internet exposure of ICS/SCADA and OT management interfaces** — place all remote access behind VPNs or jump hosts with strong authentication and network-level access controls; OT systems should never have management interfaces reachable from the public internet
- **Enforce strong, unique passwords and MFA** for all remote and administrative access to OT environments; conduct an immediate audit and rotation of all default credentials on ICS devices, PLCs, HMIs, and remote-access appliances
- **Forbid shared or generic admin accounts** — all access to OT systems should be individual, auditable, and tied to specific roles

### Network Architecture and Segmentation

- **Implement strict IT/OT network segmentation** using firewalls, DMZs, and one-way data diodes where appropriate; limit which systems can directly reach PLCs and SCADA servers
- **Segment OT zones internally** — separate control, supervisory, and historian networks; an intruder gaining access to one zone should not have direct visibility or control over others

### Monitoring and Incident Response

- **Continuously monitor remote logins, configuration changes, and ICS parameter modifications** — alert on access from external IPs, unusual accounts, or changes outside approved maintenance windows
- **Develop and exercise OT-specific incident response runbooks** covering safe fallback modes, manual operations, and re-baselining compromised systems; water utilities should be able to operate manually during a cyber incident
- **Integrate ICS telemetry into SIEM and threat detection** — anomalous changes to pump rates, filter thresholds, or dosing parameters should trigger automated alerts

### Hardening and Resilience

- **Regularly audit OT devices** for default passwords, outdated firmware, unnecessary exposed services, and unauthorized configuration changes
- **Maintain tested, offline backups of ICS configurations** to enable rapid rebuild and re-baseline of compromised systems without extended downtime

### Government and National Security

- **Treat water infrastructure intrusions as serious hybrid attacks** — classify them at the national security level and integrate them into deterrence, attribution, and response frameworks rather than treating them as low-impact incidents
- **Improve information sharing** between intelligence agencies, sector regulators, and individual utilities — smaller municipalities lack the resources to detect APT activity without external support; national programs and funding are needed to close this gap

## Resources

!!! info "Open-Source Reporting"
    - [Cyberattacks on Poland's Water Plants: A Blueprint for Hybrid Warfare — Security Affairs](https://securityaffairs.com/191868/security/cyberattacks-on-polands-water-plants-a-blueprint-for-hybrid-warfare.html)
    - [Polish Security Agency Reports ICS Breaches at Five Water Treatment Plants — SecurityWeek](https://www.securityweek.com/polish-security-agency-reports-ics-breaches-at-five-water-treatment-plants/)
    - [Poland Water Treatment Cyberattack — Russia and US — The Next Web](https://thenextweb.com/news/poland-water-treatment-cyberattack-russia-us)
    - [Poland Water Treatment Plants ICS Breached by Russian and Belarusian APTs — Rescana](https://www.rescana.com/post/poland-water-treatment-plants-ics-breached-by-russian-and-belarusian-apts-2025-attack-exposes-critical-infrastructure-se)

---

*Last Updated: May 11, 2026*