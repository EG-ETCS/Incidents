# Foreign Cyber Intrusions Targeting Two Colorado Water Utilities
![alt text](images/Colorado.png)

**Water Utilities**{.cve-chip} **Operational Technology (OT)**{.cve-chip} **ICS/SCADA**{.cve-chip} **Foreign Actors**{.cve-chip} **Service Disruption Attempt**{.cve-chip}

## Overview

Foreign threat actors targeted the OT environments of two small private water utilities in Colorado in late August 2026. Reported attacker actions included modifying equipment settings, disabling remote access and alarms, and altering pumping cycles in what officials described as disruption attempts.

Colorado authorities stated the incidents were brief and were addressed by the providers. Public reporting indicates no impact to drinking-water quality, treatment processes, customer service, or public safety. The affected utilities have not been publicly identified.

## Technical Details

### Affected Targets

- Two small private water utilities in Colorado, United States.
- Utilities reportedly serve fewer than 200 people (in total or individually, depending on source wording).
- Exact utility names, locations, and customer counts are not publicly disclosed.

### Incident Timeline

- Intrusions occurred in late August 2026.
- Public reporting followed on September 21, 2026.

### Confirmed Attacker Actions

- Changed equipment settings.
- Disabled remote access.
- Disabled alarms.
- Altered pumping cycles.
- Activity characterized as attempted operational disruption.

### Technology Context

- Target environment: water-sector OT/ICS systems supporting pumping and treatment operations.
- Specific PLC/SCADA/HMI products, firmware versions, access pathways, and network architecture details remain undisclosed.

### Broader Exposure Context (Not Confirmed for Colorado)

- Recent CISA water-sector guidance highlights risk from internet-exposed PLC infrastructure, including cellular-connected PLC deployments lacking secure gateways/firewalls.
- Earlier 2026 incidents in other states involved remote access to exposed PLCs with password/IP changes and alarm/process interference.
- Public reporting does not confirm the Colorado utilities used the same exposure model or initial-access route.

### Attribution and Exploitation Status

- Colorado authorities described actors as foreign.
- Broader references to Iranian-backed activity exist in national context discussions.
- No named threat group, no confirmed Iran attribution for this specific event, and no published forensic evidence tying it to a known campaign.
- No publicly identified CVE, malware family, exploit chain, or credential-compromise mechanism.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Sector** | Water utility / critical infrastructure |
| **Incident Type** | Unauthorized OT configuration manipulation |
| **Confirmed Actions** | Settings changes, alarm disablement, remote-access disablement, pumping-cycle modification |
| **Service Impact** | No reported effect on water quality, treatment, service delivery, or public safety |
| **Attribution Status** | Foreign actors stated by authorities; Iran linkage unconfirmed for this incident |
| **Root Access Vector** | Not publicly disclosed |

## Affected Products

- Water-utility OT environments operating pumps, treatment controls, and alarm/remote-access functions.
- Potentially relevant components include PLCs, SCADA servers, HMIs, remote telemetry, and engineering stations.
- Exact vendor and product details are not publicly available.

## Attack Scenario

1. Attackers gain unauthorized remote or administrative access to water-utility OT systems (specific path unknown).
2. Adversary modifies control-related settings.
3. Remote access and alarming functions are disabled, reducing operator visibility/response options.
4. Pumping cycles are altered to create operational disruption conditions.
5. Utility operators detect and address the activity, then notify state authorities.
6. Service/treatment and public-safety impacts are avoided through rapid response.

## Impact Assessment

=== "Confirmed Impact"

    - Unauthorized manipulation of OT settings at two private Colorado water utilities
    - Alarm and remote-access disablement plus pumping-cycle changes were reported
    - No reported impact to drinking-water quality, treatment, customer service, or public safety

=== "Potential Impact"

    - Alarm disablement and remote-access loss can delay detection and response
    - Pumping-cycle manipulation can affect pressure, supply continuity, treatment timing, and equipment health depending on plant design
    - If not contained, similar activity could contribute to outages or unsafe operating conditions

=== "Criticality"

    - **High** due to confirmed unauthorized control changes in critical-infrastructure OT environments, despite no reported service or safety outcomes

## Mitigation Strategies

### Remove Direct Internet Exposure

- Identify and eliminate direct public exposure of PLCs, SCADA servers, HMIs, telemetry devices, and OT admin interfaces.
- Avoid direct cellular-to-PLC internet connectivity without secured gateways and filtering controls.

### Secure Remote Access

- Route required remote OT access through hardened VPN or dedicated jump hosts.
- Enforce MFA, unique named accounts, least privilege, IP allowlisting, detailed logging, and time-bounded access.
- Remove unused vendor/legacy remote-access pathways and undocumented modem paths.

### Protect Configuration Integrity

- Restrict who can change pump logic, alarm behavior, setpoints, and remote-access configuration.
- Require change approvals and maintain immutable configuration-change logging.
- Alert on alarm disablement, schedule/setpoint drift, unexpected password/IP changes, and telemetry loss.

### Maintain Safe Operations and Recovery

- Keep offline known-good backups of PLC logic, HMI projects, and engineering files.
- Exercise manual-control and safe-shutdown procedures regularly.
- Validate ability to confirm water quality/treatment status when digital telemetry is unavailable.

### Segment IT and OT

- Separate corporate IT, customer/billing, third-party/vendor access, and internet-facing services from OT networks.
- Permit only documented and necessary flows between OT assets.

### Monitor and Coordinate

- Monitor OT traffic and logs for anomalous commands, new remote sessions, and suspicious outbound connections.
- Report suspected OT compromise rapidly to relevant CERT/regulators/law enforcement/sector ISAC channels.
- Review current CISA water-sector hardening guidance and perform external attack-surface assessments.

## Resources and References

!!! info "Public Reporting"
    - [Foreign Hackers Target Two Colorado Water Utilities](https://securityaffairs.com/199480/ics-scada/foreign-hackers-target-two-colorado-water-utilities.html)

---

*Last Updated: September 22, 2026*
