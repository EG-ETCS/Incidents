# CVE-2026-32746 - Critical Telnetd Buffer Overflow Vulnerability
![alt text](images/telnetd.png)

**GNU Inetutils**{.cve-chip} **Buffer Overflow**{.cve-chip} **Remote Code Execution**{.cve-chip}

## Overview

CVE-2026-32746 is a critical vulnerability in the GNU Inetutils Telnet server (`telnetd`) that may allow remote attackers to trigger memory corruption and potentially execute arbitrary code.

The flaw is tied to unsafe handling of specific Telnet protocol options. Exploitation can occur over the network when vulnerable Telnet services are exposed.

## Technical Specifications

| Field | Details |
|-------|---------|
| **Identifier** | CVE-2026-32746 |
| **Vulnerability Type** | Buffer Overflow (CWE-120) |
| **CVSS Score** | 9.8(Critical) |
| **Affected Component** | GNU Inetutils `telnetd` |
| **Root Cause** | Improper bounds checking in LINEMODE SLC handling (`add_slc`) |
| **Trigger** | Crafted LINEMODE SLC Telnet packets |
| **Exposure Conditions** | Telnet service reachable on port 23; no authentication required |

## Affected Products

- Systems running vulnerable GNU Inetutils `telnetd`.
- Internet-facing or internally reachable Telnet services on TCP port 23.
- Environments still using legacy Telnet for remote administration.

## PoC Video

<iframe width="100%" height="420" src="https://www.youtube.com/embed/18rSQfBABeE" title="Telnetd CVE-2026-32746 PoC" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

## Technical Details

- The vulnerability is caused by insufficient bounds checks in the LINEMODE SLC processing path.
- Specifically, unsafe operations in `add_slc` can be triggered with crafted protocol fields.
- Malformed LINEMODE SLC packets may cause out-of-bounds memory writes.
- Because exploitation can occur before authentication, externally reachable services are high risk.
- Successful exploitation may lead to code execution, depending on platform protections and runtime conditions.

## Attack Scenario

1. An attacker scans target networks for exposed Telnet services on port 23.
2. A vulnerable GNU Inetutils `telnetd` instance is identified.
3. The attacker initiates a Telnet session to the service.
4. Crafted LINEMODE SLC payloads are sent to trigger memory corruption.
5. The buffer overflow is exploited to crash the process or achieve code execution.
6. The attacker may obtain remote shell access and escalate to persistent foothold in the environment.

## Impact Assessment

=== "Technical Impact"
    Exploitation can enable remote code execution, service crash conditions, and unauthorized memory manipulation in exposed Telnet services.

=== "System and Data Impact"
    Successful compromise may result in full system takeover (often with elevated privileges), data exfiltration, and unauthorized data modification.

=== "Enterprise Risk Impact"
    Compromised hosts can be used for persistence and lateral movement, increasing broader network and operational risk.

## Mitigation Strategies

- Update GNU Inetutils to a patched version as soon as available from trusted sources.
- Disable Telnet services where not strictly required.
- Block or tightly restrict TCP port 23 via firewalls.
- Limit management access to VPN or trusted source IP ranges.
- Replace Telnet with SSH for remote administration.
- Monitor logs for malformed Telnet requests and suspicious connection patterns.

## Resources

!!! info "Open-Source Reporting"
    - [Critical Unpatched Telnetd Flaw (CVE-2026-32746) Enables Unauthenticated Root RCE via Port 23](https://thehackernews.com/2026/03/critical-telnetd-flaw-cve-2026-32746.html)
    - [CVE-2026-32746 - GNU inetutils telnetd LINEMODE SLC Buffer Overflow](https://cvefeed.io/vuln/detail/CVE-2026-32746)
    - [NVD - CVE-2026-32746](https://nvd.nist.gov/vuln/detail/CVE-2026-32746)

---
*Last Updated: March 18, 2026*