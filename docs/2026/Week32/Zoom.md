# ZOOMSDAY – Zoom Zero-Click Remote Code Execution Vulnerability
![alt text](images/Zoom.png)

**CVE-2026-53413**{.cve-chip} **CVE-2026-53414**{.cve-chip} **CVE-2026-53415**{.cve-chip} **Zero-Click RCE**{.cve-chip} **Zoom Annotation Protocol**{.cve-chip}

## Overview

Researchers from A Security discovered vulnerabilities in Zoom's annotation functionality. The most severe issue, CVE-2026-53413, could allow a malicious participant in a Zoom meeting to compromise another participant's Zoom client and potentially execute arbitrary code.

The attack path is zero-click: it does not require the victim to click a link, download a file, or interact with prompts.

<iframe width="100%" height="500" src="https://www.youtube.com/embed/wejvsWneFko" title="Zoomsday" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

## Technical Details

The vulnerabilities reside in the proprietary protocol used by Zoom's annotation feature.

- CVE-2026-53413: buffer-overwrite and memory-corruption vulnerability
- CVE-2026-53414: buffer over-read vulnerability
- CVE-2026-53415: use-after-free vulnerability

Zoom's bulletin maps these to ZSB-26015, ZSB-26016, and ZSB-26017, respectively.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Primary Vulnerability** | CVE-2026-53413 |
| **Additional Vulnerabilities** | CVE-2026-53414, CVE-2026-53415 |
| **Vulnerability Domain** | Zoom annotation protocol parser and memory handling |
| **Exploit Prerequisite** | Attacker participates in or hosts a meeting with victim present |
| **User Interaction** | Not required (zero-click) |
| **Potential Outcome** | Remote code execution on victim endpoint |
| **Vendor Bulletin IDs** | ZSB-26015, ZSB-26016, ZSB-26017 |
| **Affected Components** | Zoom Workplace, Zoom VDI, Zoom Rooms, Meeting SDK branches (version-dependent) |
| **Fix Guidance** | Zoom Workplace 7.1.5 / 7.0.6 branches and component-specific fixed releases |

## Affected Products

- Zoom clients using vulnerable annotation protocol implementations
- Zoom Workplace deployments on affected version branches
- Zoom VDI, Zoom Rooms, and Meeting SDK deployments pending component-specific updates
- Enterprise endpoints used by privileged users, executives, administrators, and presenters

## Attack Scenario

1. Attacker joins or hosts a Zoom meeting.
2. Attacker sends specially crafted annotation data via Zoom's annotation protocol.
3. The receiving Zoom client automatically processes the malicious data.
4. Memory corruption is triggered in vulnerable client code.
5. CVE-2026-53413 exploitation may result in remote code execution on the victim machine.
6. Victim interaction is not required at any stage.
7. Attacker may then deploy payloads, establish persistence, and pivot to broader enterprise targets.

## Impact Assessment

=== "Integrity"

    - Successful code execution can allow attacker modification of local system state and security controls
    - Compromise may enable tampering with enterprise data and application settings on affected endpoints
    - Privileged endpoint compromise can undermine trust boundaries across internal environments

=== "Confidentiality"

    - Attackers may access sensitive files, session artifacts, and stored credentials from compromised clients
    - Stolen credentials or tokens can expose additional corporate systems and SaaS platforms
    - Presenter and participant endpoints may both become pathways to confidential information theft

=== "Availability"

    - Endpoint compromise can disrupt user operations and require host isolation and rebuild
    - Malware installation and follow-on tooling may degrade endpoint and service performance
    - Incident response actions may temporarily reduce meeting-service availability for high-risk users

## Mitigation Strategies

### Immediate Patching

- Update Zoom clients immediately to fixed versions.
- Apply Zoom Workplace fixes on supported branches (7.1.5 / 7.0.6 as reported).
- Update Zoom VDI, Rooms, and Meeting SDK separately according to their own affected/fixed version matrices.

### Access and Exposure Controls

- Inventory Zoom installations and prioritize remediation based on exposure and privilege.
- Restrict meeting access using authentication, waiting rooms, and controlled invitations.
- Disable or restrict annotation where operationally possible until patching is complete.

### Monitoring and Response

- Monitor endpoints for suspicious processes or network activity originating from Zoom.
- Prioritize detection and hardening for executive, administrator, and other privileged systems.
- Investigate anomalous behavior in or around meeting sessions and rapidly isolate suspected compromised hosts.

## Resources and References

!!! info "Public Reporting"
    - [Zoom Annotation Flaws Could Let a Meeting Participant Hijack Another Attendee's Client](https://thehackernews.com/2026/08/zoom-annotation-flaws-could-let-meeting.html)
    - [Zoom Patches "Zoomsday" Zero-Click Flaw Enabling Remote Code Execution](https://securityaffairs.com/197042/hacking/zoom-patches-zoomsday-zero-click-flaw-enabling-remote-code-execution.html)
    - [A Zoom Screen-Sharing Bug Let Anyone Take Over Other Devices on a Call | WIRED](https://www.wired.com/story/a-zoom-screen-sharing-bug-let-anyone-take-over-other-devices-on-a-call/)
    - [Zoom Zero-Click RCE CVE-2026-53413: Update Now](https://blog.gridinsoft.com/zoom-zero-click-rce-cve-2026-53413/)

---

*Last Updated: August 12, 2026*
