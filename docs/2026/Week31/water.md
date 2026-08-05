# Multi-state U.S. Water-System PLC Cyberattacks (Minnesota, Michigan, Georgia, and Other States)
![alt text](images/water.png)

**Water Utility OT Threat**{.cve-chip} **PLC Intrusions**{.cve-chip} **Multi-State Disruption**{.cve-chip} **Iran-Linked Suspicion**{.cve-chip} **Critical Infrastructure Risk**{.cve-chip}

## Overview

Recent reporting indicates that Georgia and Michigan joined Minnesota in disclosing malicious cyber activity targeting municipal water-system operational technology (OT).

FBI advisory information and sector coverage indicate incidents affecting utilities in at least seven U.S. states since late July 2026, involving unauthorized PLC access and operational degradation. Iran-linked actors are widely treated as leading suspects in open reporting, but public formal attribution remains pending.

## Technical Specifications

### Campaign Scope and Targets

- FBI reporting indicates incidents in Water and Wastewater Systems (WWS) across at least seven states since July 27, 2026.
- Mentioned states include Minnesota, Michigan, Georgia, Wisconsin, and South Dakota, with additional jurisdictions not publicly named.
- Some reported incidents included measurable degradation of water operations.

### Targeted Technology - PLCs and OT

- FBI guidance references observed activity against Rockwell Automation / Allen-Bradley PLCs.
- CISA advisory AA26-097A (updated July 22, 2026) indicates expanded risk to Schneider Electric, Siemens, and potentially other PLC environments.
- CISA warns that water, energy, and local-government facilities share similar exposure patterns.

### Observed Attack Behavior

- Adversaries target internet-exposed controllers and weakly protected remote-access paths.
- Reported behaviors include unauthorized parameter changes, credential modifications, and operator lockout patterns.
- CISA describes a significant increase in activity against exposed PLC assets in the WWS sector.

### Minnesota Wave and Advisory Linkage

- The earlier Minnesota wave impacted over 30 municipal systems with coordinated OT disruption.
- Open-source assessments noted alignment with Iranian-affiliated PLC-focused campaign patterns documented by CISA in April and July 2026.
- Advisory alignment does not itself constitute formal attribution.

## Affected Products

- Water and wastewater OT systems using PLC-controlled process automation
- SCADA/HMI environments dependent on stable controller communications
- Internet-exposed industrial controllers and remote engineering interfaces
- Multi-vendor PLC estates including Rockwell, Schneider, and Siemens ecosystems

## Attack Scenario

1. Exposure and reconnaissance: attackers discover internet-facing PLC/OT interfaces.
2. Unauthorized access: weak credentials, remote pathways, or known weaknesses are used to enter control environments.
3. Configuration sabotage and lockout: operator credentials, network settings, or control parameters are altered.
4. Operational impact: monitoring/control degradation forces manual workflows and emergency response procedures.
5. Expansion beyond Minnesota: similar TTPs are reported across multiple states in the same timeframe.

## Impact Assessment

=== "Integrity"

    - Unauthorized PLC changes can alter process behavior and undermine control-system trust
    - Controller lockouts and configuration tampering increase risk of persistent manipulation
    - Coordinated multi-state activity suggests repeatable campaign tradecraft against municipal OT

=== "Confidentiality"

    - Exposed OT and remote-access services may reveal architecture and operational details
    - Credential reuse and weak access controls can expose sensitive engineering pathways
    - Intelligence gained from one utility can support follow-on targeting in other jurisdictions

=== "Availability"

    - Utilities may lose automated visibility/control and shift to manual operations
    - Disruptions can affect pump, valve, and treatment workflows and increase response burden
    - Officials report no confirmed contamination in cited incidents, but continuity pressure remains high

## Mitigation Strategies

### Remove PLCs and OT from the Public Internet

- Disconnect internet-exposed PLCs and direct OT management interfaces.
- Route remote operations through secure VPN/gateway models rather than direct controller exposure.

### Harden Authentication and Access Paths

- Eliminate default/weak passwords on PLCs and engineering workstations.
- Apply strong credential policy and MFA where operationally feasible.
- Implement IP allowlisting for trusted engineering endpoints.

### Asset Discovery and Undocumented Connectivity

- Audit all external connectivity paths, including cellular modems and vendor-installed remote channels.
- Validate discovered access paths against approved network architecture.

### Segmentation and Monitoring

- Enforce strict OT/IT segmentation and minimize controller reachability.
- Monitor for unauthorized PLC configuration changes, credential updates, and abnormal remote access events.

### Reporting and Coordination

- Report suspicious activity to FBI IC3, CISA, and sector information-sharing channels such as WaterISAC.
- Operationalize indicators and TTP guidance from AA26-097A and related joint advisories.

## Resources and References

!!! info "Public Reporting"
    - [Georgia and Michigan disclose water-system attacks linked to broader campaign reporting](https://www.theregister.com/security/2026/08/03/georgia-michigan-say-water-systems-hacked-by-iran-tied-crew/5282262)
    - [CISA advisory AA26-097A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a)
    - [U.S. investigation of suspected Iran-linked activity against Minnesota water systems](https://www.cbsnews.com/news/us-investigating-iran-cyberattack-minnesota-water-systems/)

---

*Last Updated: August 5, 2026*
