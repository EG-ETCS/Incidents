# Unisoc VoLTE Video Call Exploit Chain – Modem-to-Android Kernel Privilege Escalation
![alt text](images/VoLTE.png)

**Unisoc Baseband Security**{.cve-chip} **VoLTE Attack Surface**{.cve-chip} **Modem RCE**{.cve-chip} **CWE-1189**{.cve-chip} **Kernel Privilege Escalation**{.cve-chip}

## Overview

Security researchers from SSD Secure Disclosure disclosed a two-stage exploit chain affecting devices using vulnerable Unisoc modem firmware.

The chain combines a previously disclosed modem RCE vulnerability with a newly disclosed modem-to-application-processor privilege-escalation weakness. A malicious VoLTE video call can be used as the entry point, potentially allowing an attacker to move from the cellular modem into the Android kernel.

## Technical Details

The first stage involves malicious SIP and SDP data processed by the Unisoc modem during VoLTE video-call setup. The earlier vulnerability allows an attacker to obtain code execution within the modem.

The second stage abuses insufficient isolation between the Unisoc modem processor and the application processor. Researchers classified the new weakness as CWE-1189, Improper Isolation of Shared Resources on a System-on-Chip.

The issue was demonstrated on Unisoc platforms including T606, T612, and T7250, with testing involving devices such as the Motorola E13, Realme C33, and Xiaomi Redmi A5.

The key concern is that modem-side execution can potentially cross the intended security boundary and reach Android kernel memory, resulting in kernel-level compromise.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Exploit Model** | Two-stage modem-to-kernel exploit chain |
| **Stage 1** | Malicious SIP/SDP during VoLTE video-call setup leading to modem RCE |
| **Stage 2** | Modem-to-application-processor boundary bypass enabling kernel-relevant impact |
| **Weakness Class** | CWE-1189 (Improper Isolation of Shared Resources on a SoC) |
| **Entry Vector** | VoLTE video call over cellular/IMS infrastructure |
| **Demonstrated Chipsets** | Unisoc T606, T612, T7250 |
| **Example Tested Devices** | Motorola E13, Realme C33, Xiaomi Redmi A5 |
| **Attacker Prerequisites (Demo Context)** | Control of private 4G network and victim answering video call |
| **Patch Status at Disclosure** | No fix reported for newly disclosed issue as of August 17 |

## Affected Products

- Android devices using vulnerable Unisoc modem firmware on affected chipset families
- Devices using Unisoc T606, T612, and T7250 in tested/demonstrated scope
- Enterprise and consumer environments relying on VoLTE video-calling functionality
- Organizations that track only Android patch levels but not modem/baseband firmware state

## Attack Scenario

A representative chain is:

Attacker-controlled cellular infrastructure -> malicious SIP/SDP -> VoLTE video call -> Unisoc modem RCE -> modem/processor isolation bypass -> Android kernel execution

Researchers demonstrated the chain in a controlled lab environment using cellular and IMS infrastructure. The complete demonstrated scenario required attacker control over a private 4G network, and the victim was required to answer the video call.

## Impact Assessment

=== "Integrity"

    - Kernel-level compromise can allow attacker modification of core Android system behavior
    - Security controls and trusted processes may be altered from a privileged execution context
    - Compromise can persist beyond normal application-level trust boundaries

=== "Confidentiality"

    - Privileged access can expose sensitive device data, communications, and credentials
    - Surveillance risk increases due to access beneath normal mobile app isolation layers
    - Communications and metadata handling paths may be observable or manipulable after compromise

=== "Availability"

    - Kernel-level exploitation can destabilize device operation or interrupt core functions
    - Security remediation may require urgent firmware updates and possible device replacement
    - Lack of immediate vendor patch availability can prolong operational exposure windows

## Mitigation Strategies

### Patch and Asset Management

- Install OEM firmware and modem updates as soon as they become available.
- Maintain the latest Android security updates on all managed devices.
- Identify devices using vulnerable Unisoc chipsets and modem firmware revisions.

### Exposure Reduction

- For high-risk environments, restrict or disable VoLTE/video-calling functionality where feasible.
- Maintain a complete inventory of mobile devices including baseband and modem firmware versions.
- Replace unsupported devices if the vendor does not provide remediation.

### Monitoring and Detection

- Monitor cellular infrastructure and IMS/SIP traffic for anomalous signaling behavior.
- Treat baseband firmware as part of the organization security perimeter.
- Prioritize threat hunting for suspicious behavior on devices with affected Unisoc platforms.

### Risk Context

- At disclosure time on August 17, researchers reported no response from Unisoc and no fix available for the newly disclosed issue.

## Resources and References

!!! info "Public Reporting"
    - [Unisoc VoLTE Video Call Exploit Chain Can Give Attackers Full Android Kernel Access](https://thehackernews.com/2026/08/unisoc-volte-video-call-exploit-chain.html)

---

*Last Updated: August 18, 2026*
