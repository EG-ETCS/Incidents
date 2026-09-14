# LG Smart TV Data Collection
![alt text](images/LG.png)

**Smart TV Privacy**{.cve-chip} **webOS**{.cve-chip} **ACR Telemetry**{.cve-chip} **IoT Exposure**{.cve-chip} **Standby Concerns**{.cve-chip}

<iframe width="1768" height="994" src="https://www.youtube.com/embed/6IFVTcM28KA" title="216,000,000 Spy TVs | The LG Smart TV Problem" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

## Overview

Researchers raised privacy concerns about data-collection capabilities in LG Smart TVs running webOS, focusing on Automatic Content Recognition (ACR), telemetry behavior, local-network discovery, and claims regarding possible ambient audio handling while devices appear in standby.

LG publicly rejected characterization that its TVs secretly record users and stated voice processing is local and governed by user controls and consent settings. The incident therefore centers on disputed privacy and data-practice concerns rather than a confirmed specific malware campaign.

## Technical Details

LG Smart TVs are network-connected IoT systems that communicate with cloud services and local network resources.

### Reported/Discussed Capability Areas

- ACR functions that can identify viewed content, including content delivered through HDMI inputs.
- Telemetry and advertising-related usage data collection.
- Local network and device discovery behavior.
- Microphone/voice feature behavior and user-expectation concerns around standby state.

### Standby Technical Context

- Standby mode may not equal full power-off.
- Portions of webOS and network-connected components can remain active depending on configuration and enabled features.
- Privacy/security risk posture depends on enabled features, firmware state, network exposure, and account settings.

### Evidence and Dispute Context

- Public reporting contains allegations and interpretations of observed behavior.
- LG disputes claims of secret room-audio recording and emphasizes user-controlled settings and consent pathways.
- Classification: privacy-risk and telemetry-governance controversy with security implications if compromise occurs.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Product Family** | LG Smart TVs (webOS) |
| **Primary Concern Type** | Privacy and data-collection practices |
| **Reported Features in Scope** | ACR/Live Plus, telemetry, ad-related profiling, local network discovery |
| **Voice/Audio Concern** | Allegations of ambient-audio handling in standby context (disputed by vendor) |
| **Operational State Nuance** | Standby may retain active OS/network components |
| **Confirmed Malware Exploit in This Case** | Not established in cited reporting |

## Affected Products

- LG Smart TVs running webOS with ACR/telemetry/voice-related features enabled.
- Home and enterprise environments where TVs remain internet-connected.
- Organizations integrating Smart TVs into business or sensitive network zones.

## Attack Scenario

### Privacy/Data-Collection Scenario

1. TV remains connected to internet/cloud services.
2. Viewing/activity metadata is collected through enabled ACR/telemetry features.
3. Data may be associated with device and account/profile contexts.
4. Data can be transmitted to backend systems for analytics, advertising, or related functions.

### Security Abuse Scenario (Potential)

1. Attacker compromises TV or vulnerable webOS component.
2. Device network position, storage, and enabled sensors/features are abused.
3. TV could be used for surveillance, reconnaissance, or exfiltration.

The second path is a potential risk model, not evidence of a confirmed attack in this incident.

## Impact Assessment

=== "Privacy and Trust Impact"

    - Potential loss of user privacy and informed-consent confidence
    - Detailed viewing and behavioral profiling concerns
    - Reputational and trust impact for consumer and institutional deployments

=== "Network Exposure Impact"

    - Potential visibility into local-network device patterns
    - Increased concern where Smart TVs share networks with sensitive assets

=== "Potential Post-Compromise Security Impact"

    - If compromised, TV features could support surveillance, reconnaissance, and data exfiltration
    - This is a contingent risk path rather than a confirmed observed outcome in this incident

## Mitigation Strategies

### Reduce Data Collection Surface

- Disable ACR/Live Plus and unnecessary viewing-information features.
- Disable personalized advertising and non-essential telemetry where available.
- Disable voice/voice-recognition features if not required.

### Strengthen Device and Account Controls

- Review LG privacy settings, consent options, and account permissions.
- Keep webOS and TV firmware fully updated.
- Review active app permissions and remove unneeded applications/services.

### Network Hardening

- Place Smart TVs on isolated IoT/VLAN network segments.
- Restrict unnecessary outbound traffic at router/firewall level.
- Monitor unusual DNS/HTTPS patterns originating from TV devices.
- Avoid placing Smart TVs on sensitive corporate/production networks.

### Enterprise Governance

- Maintain asset inventory and baseline expected TV network behavior.
- Include IoT endpoints such as Smart TVs in security monitoring and incident-response workflows.

## Resources and References

!!! info "Public Reporting"
    - [LG accused of 'egregious invasion of privacy' over TV data collection](https://www.theregister.com/security/2026/09/08/lg-accused-of-egregious-invasion-of-privacy-over-tv-data-collection/5294956)
    - [LG Smart TVs Accused of Recording Room Audio in Standby, How to Stop It](https://lynnwoodtimes.com/2026/09/08/lg-smart/)
    - [LG smart TVs can record your conversations and scan nearby Wi-Fi networks, claims report](https://timesofindia.indiatimes.com/technology/tv-television/lg-smart-tvs-can-record-your-conversations-and-scan-nearby-wi-fi-networks-claims-report/articleshow/133916986.cms)

---

*Last Updated: September 14, 2026*