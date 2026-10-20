# WPSplinter - Broadcom Wi-Fi / WPS Implementation Vulnerability
![alt text](images/WPSplinter.png)

**WPSplinter**{.cve-chip} **Broadcom Wi-Fi**{.cve-chip} **WPS / EAP Reassembly**{.cve-chip} **Unauthenticated RCE**{.cve-chip} **Proximity Attack**{.cve-chip}

## Overview

A vulnerability in Broadcom's proprietary Wi-Fi implementation, present since at least 2010, allows attackers within wireless range to potentially execute arbitrary code on vulnerable routers without authentication.

The flaw affects WPS-related EAP message reassembly. An incomplete fix was reportedly released in 2018, leaving legacy devices exposed. The researcher demonstrated successful exploitation on gateways used by Belgian ISPs.

## Technical Details

- Affected component: Broadcom proprietary 802.11 / WPS implementation.
- Root cause: Memory corruption associated with improper handling of fragmented EAP messages during WPS processing.
- Attack prerequisites: Wireless proximity; no Wi-Fi password or completed WPS enrollment required.
- Potential result: Information disclosure and unauthenticated remote code execution.
- Affected chipset families: BCM3380, BCM3383, BCM33834, BCM3390, BCM65xx and BCM68xx.
- CVE status: No CVE identifier was assigned at the time of public disclosure.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Vulnerability Name** | WPSplinter |
| **Affected Stack** | Broadcom proprietary 802.11 / WPS implementation |
| **Weakness Class** | Memory corruption in fragmented EAP message handling |
| **Attack Requirement** | Attacker within wireless transmission range |
| **Authentication Requirement** | None (no Wi-Fi password or completed WPS enrollment required) |
| **Impact Potential** | Information disclosure and unauthenticated code execution |
| **Chipset Families Referenced** | BCM3380, BCM3383, BCM33834, BCM3390, BCM65xx, BCM68xx |
| **Disclosure CVE Status** | No CVE assigned at disclosure time |

## Affected Products

- Routers and gateways using affected Broadcom chipset families and vulnerable firmware branches.
- Legacy ISP-provided gateway fleets that did not receive complete remediation.

## Attack Scenario

1. An attacker approaches a vulnerable router within Wi-Fi transmission range.
2. The attacker transmits specially crafted wireless messages targeting WPS EAP message-processing code.
3. Improper fragment handling triggers memory corruption.
4. The attacker leverages the flaw to execute code without authentication.
5. Depending on achieved privileges, the attacker may extract Wi-Fi credentials, establish command execution, manipulate traffic, or pivot further into connected networks.

The researcher demonstrated credential extraction on an Orange Belgium ASKEY TCG3000 and a reverse shell on a Proximus BBOX3V+ gateway. These were controlled research demonstrations, not proof of widespread exploitation in the wild.

## Impact Assessment

=== "Security Impact"

    - Potential exposure of Wi-Fi passwords and accessible traffic
    - Unauthorized modification of router configuration or traffic paths

=== "Availability and Network Impact"

    - Possible router disruption or denial-of-service outcomes
    - Potential compromise of devices communicating through the affected router

=== "Operational Risk"

    - Difficult detection and remediation on unsupported ISP-provided gateways
    - Research estimates indicate about 1.56 million potentially affected gateways across three Belgian ISP fleets; this is an estimate, not a verified exploitable count

## Mitigation Strategies

1. Identify affected router models, Broadcom chipsets, and firmware versions.
2. Contact the router manufacturer or ISP to confirm vulnerability status and available remediation.
3. Apply verified firmware updates or vendor-provided fixes.
4. Replace affected devices if no effective security update is available.
5. Disable WPS as general security hygiene, but do not treat this alone as a confirmed fix.
6. Segment sensitive systems from potentially vulnerable routers and monitor for unusual wireless activity or unexpected router configuration changes.
7. If compromise is suspected, secure or replace the router before changing Wi-Fi and administrator passwords.
8. Track vendor advisories and updated affected-device lists as investigation details evolve.

## Resources and References

!!! info "Public Reporting"
    1. [16-Year-Old Broadcom Wi-Fi Bug Lets Attackers Take Over Routers Without a Password](https://securityaffairs.com/201268/iot/16-year-old-broadcom-wi-fi-bug-lets-attackers-take-over-routers-without-a-password.html)
    2. [Broadcom Wi-Fi bug turns sweet 16, still lets strangers hijack your router](https://www.theregister.com/networks/2026/10/19/broadcom-wi-fi-bug-turns-sweet-16-still-lets-strangers-hijack-your-router/5303771?utm_source=chatgpt.com)
    3. [Unpatched Broadcom Wi-Fi Flaw Lets Attackers in Range Run Code as Root on Routers](https://thehackernews.com/2026/10/unpatched-broadcom-wi-fi-flaw-lets.html)

---

*Last Updated: October 20, 2026*
