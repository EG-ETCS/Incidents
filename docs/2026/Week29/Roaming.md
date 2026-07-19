# Iranian Mobile Tracking Campaign Targeting U.S. Military Personnel via SS7 Roaming and AdTech Data
![alt text](images/Roaming.png)

**SS7 Abuse**{.cve-chip} **AdTech Data Correlation**{.cve-chip} **Location Intelligence**{.cve-chip} **OPSEC Risk**{.cve-chip} **Telecom Signaling**{.cve-chip}

## Overview

Reporting indicates Iranian-linked actors used a hybrid intelligence-collection approach that combined legacy telecom signaling weaknesses with commercial advertising data to track U.S. military personnel and contractors in the Gulf region. The operation focused on identifying physical location and movement patterns rather than infecting mobile devices.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Campaign Type** | Location intelligence and movement profiling |
| **Primary Telecom Vector** | Abuse of SS7 roaming-related signaling queries |
| **Example Signaling Messages** | AnyTimeInterrogation (ATI), ProvideSubscriberInfo (PSI) |
| **Commercial Data Source** | AdTech datasets containing GPS, ad IDs, Wi-Fi, and Bluetooth metadata |
| **Correlation Inputs** | Telecom signaling, AdTech data, social media, satellite imagery, other intelligence sources |
| **Operational Goal** | Identify hotels, facilities, routes, and routine patterns tied to personnel |
| **Malware Requirement** | None reported (collection and correlation operation) |
| **Security Boundary Impacted** | Telecom trust model plus consumer data-broker ecosystem |

## Affected Products

- Mobile subscribers using international roaming in sensitive operational regions
- Telecom operators with weak SS7/Diameter filtering and monitoring controls
- Organizations whose personnel expose location via mobile apps and advertising ecosystems
- High-value defense and contractor populations with blended personal/operational device usage

## Attack Scenario

1. U.S. military personnel and contractors travel internationally with mobile devices.
2. Devices attach to local operators through roaming relationships.
3. Threat actors abuse SS7 signaling requests to query subscriber location metadata.
4. In parallel, commercial AdTech datasets provide GPS history and advertising identifiers.
5. Analysts correlate signaling results with AdTech and open-source intelligence to derive movement profiles.
6. The resulting intelligence can support operational planning and potential kinetic targeting decisions.

## Impact Assessment

=== "Integrity"

    - Trust assumptions in telecom signaling and data-sharing ecosystems are undermined
    - Operational planning can be influenced by adversary access to near-real-time movement context
    - Defensive decision-making may be distorted by covert intelligence collection visibility

=== "Confidentiality"

    - Sensitive location data for personnel, routes, and facilities may be exposed
    - Pattern-of-life analysis can reveal routines, high-value nodes, and mission correlations
    - Commercial data trails can leak mission-adjacent information without direct device compromise

=== "Availability"

    - Elevated force-protection response and communication restrictions may disrupt operations
    - Mitigation activities (device policy changes, access limitations) can reduce workflow efficiency
    - High OPSEC alert states can strain staffing and operational continuity

## Mitigation Strategies

### Immediate Actions

- Deploy and tune SS7/Diameter signaling firewalls across carrier interconnect points
- Filter unauthorized roaming location requests and enforce strict signaling policies
- Identify and restrict high-risk applications collecting precise background location

### Short-term Measures

- Limit advertising identifiers and unnecessary location permissions on mobile devices
- Disable geotagging and reduce Bluetooth/Wi-Fi broadcasting when operationally feasible
- Separate operational devices from personal devices wherever possible

### Monitoring & Detection

- Continuously monitor signaling traffic for anomalous ATI/PSI request patterns
- Track commercial data exposure and assess third-party data broker risk pathways
- Correlate telecom anomalies with travel schedules and force-protection monitoring

## Resources and References

!!! info "Public Reporting"
    - [Financial Times: US military smartphones targeted through roaming and ad tech | Congressman Pat Harrigan](https://harrigan.house.gov/media/in-the-news/financial-times-us-military-smartphones-targeted-through-roaming-and-ad-tech)
    - [How Iran used data roaming, ad tech to track US military personnel in Gulf](https://www.msn.com/en-in/news/world/how-iran-used-data-roaming-ad-tech-to-track-us-military-personnel-in-gulf/ar-AA27Xa8b?ocid=BingNewsSerp)
    - [How Iran Used Data Roaming, Ad Tech To Track US Military Personnel In Gulf](https://www.ndtv.com/world-news/how-iran-used-data-roaming-ad-tech-to-track-us-military-personnel-in-gulf-11773907)
    - [Iran Used Phone Tracking to Target US Forces: Report - Caspianpost.com](https://caspianpost.com/iran/iran-used-phone-tracking-to-target-us-forces-report)
    - [Iran used roaming systems, ad tech to track US troops in Gulf: Report - Turkiye Today](https://www.turkiyetoday.com/business/iran-used-roaming-systems-ad-tech-to-track-us-troops-in-gulf-report-3223907)

---

*Last Updated: July 19, 2026*
