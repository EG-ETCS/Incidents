# DDoS Attack on Norway’s Shared Digital Government Infrastructure
![alt text](images/DDoS.png)

**Distributed Denial of Service**{.cve-chip} **Public Sector**{.cve-chip} **Availability Attack**{.cve-chip} **Government Services**{.cve-chip} **ID Porten**{.cve-chip} **DDoS Mitigation**{.cve-chip}

## Overview

A large distributed denial-of-service (DDoS) attack disrupted Norway’s shared digital-government infrastructure from 03:38 CEST on Monday, 24 August 2026. The attack targeted infrastructure operated for the Norwegian Digitalisation Agency (Digdir) by its service provider Vivicta, affecting multiple public digital services.

The incident is a continuing availability attack, not a confirmed systems breach. Digdir reported no indication that its systems were intruded upon and no evidence of compromised personal data.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Attack Type** | Distributed Denial of Service (DDoS) |
| **Targeted Infrastructure** | Digdir shared digital-government services operated with Vivicta |
| **Affected Services** | Public-sector digital services including ID-porten and eSignering |
| **Impact Pattern** | Full outages, intermittent access, high latency, connection errors, slow logins |
| **Attack Scale** | Reportedly two to three times larger than prior Digdir DDoS incident |
| **Duration** | Ongoing for approximately 30+ hours after initial reporting |
| **Attribution** | Unattributed by Norwegian authorities; no public evidence tied to a named actor |
| **Breach Status** | No confirmed intrusion or personal-data compromise |

## Affected Products

- Digdir shared digital-government infrastructure
- Vivicta-operated hosting and service infrastructure
- ID-porten authentication platform
- eSignering electronic-signature services
- Multiple public services relying on shared government identity and transaction infrastructure

## Attack Scenario

1. Attackers generate or coordinate large volumes of malicious network traffic against Digdir/Vivicta infrastructure.
2. The traffic flood overwhelms network, application, or service capacity supporting shared public services.
3. Authentication and digital-government systems become slow, partially unavailable, or error-prone.
4. Citizens, businesses, and public-sector users encounter failed connections, long login times, and service disruptions.
5. Additional government services experience indirect disruption when they depend on the same central infrastructure.
6. Digdir and Vivicta apply traffic-handling and mitigation controls to reduce the attack and recover service availability.

## Impact Assessment

=== "Integrity"

    - No confirmed system alteration or compromise reported
    - Availability and service integrity degraded by attack traffic
    - Centralized public-service dependencies exposed as single points of failure during overload

=== "Confidentiality"

    - No evidence of personal-data compromise published by authorities
    - Sensitive but not exposed in the reported scope of the incident
    - Risk remains limited because the event is an availability attack, not a confirmed breach

=== "Availability"

    - Multiple public digital services unavailable or degraded for significant periods
    - Long login times, intermittent failures, and partial outages across identity and signature systems
    - Delays to public-sector workflows and citizen service access

## Mitigation Strategies

### Immediate Actions

- Deploy upstream filtering, scrubbing, rate limiting, and DDoS mitigation services at network and application layers.
- Prioritize critical identity, electronic-signature, and public-service endpoints during overload conditions.
- Coordinate with providers, ISPs, and hosting operators to absorb and filter malicious traffic.

### Short-term Measures

- Strengthen resilience across authentication, DNS, API, and identity gateways with regional redundancy.
- Test service failover and capacity under large-scale traffic surges.
- Review third-party dependencies and incident-response obligations with hosting and network providers.

### Monitoring & Detection

- Track baselines for traffic volume, login failures, API errors, and protocol anomalies.
- Alert on sudden, concentrated spikes affecting authentication, signing, and public-service endpoints.
- Monitor dependencies across identity, DNS, and service-provider layers during active DDoS events.

### Long-term Solutions

- Design centralized public-service platforms with distributed capacity and multi-provider resilience.
- Build emergency service prioritization and fallback procedures for critical government functions.
- Conduct joint DDoS exercise testing with providers and public-sector stakeholders.
- Maintain transparent public status communication and recovery playbooks.

## Resources and References

!!! info "Public Reporting"
    - [Massive DDoS attack disrupts Norway's government digital services | BleepingComputer](https://www.bleepingcomputer.com/news/security/massive-ddos-attack-disrupts-norways-government-digital-services/)
    - [Norwegian public services targeted by cyberattack | Malay Mail](https://www.malaymail.com/news/world/2026/08/25/norwegian-public-services-targeted-by-cyberattack/232608)
    - [Norway's digital government infrastructure hit by a new DDoS attack | SecurityAffairs](https://securityaffairs.com/197826/cyber-warfare-2/norway-s-digital-government-infrastructure-hit-by-a-new-ddos-attack.html)

---

*Last Updated: August 26, 2026*
