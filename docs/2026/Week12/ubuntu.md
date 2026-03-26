# CVE-2026-3888 - Ubuntu Desktop Snap Local Privilege Escalation
![alt text](images/ubuntu.png)

**Ubuntu Desktop**{.cve-chip} **Local Privilege Escalation**{.cve-chip} **snapd**{.cve-chip}

## Overview

CVE-2026-3888 is a local privilege escalation vulnerability affecting Ubuntu Desktop 24.04 LTS through the `snapd` stack. The flaw allows a local unprivileged user to escalate privileges to root under exploitable timing conditions.

The issue is tied to unsafe interaction between `snap-confine` and `systemd-tmpfiles`, where `/tmp/.snap` can be removed and maliciously recreated before later root-privileged processing.

## Technical Specifications

| Field | Details |
|-------|---------|
| **Identifier** | CVE-2026-3888 |
| **CVSS Score** | 7.8(High) |
| **Affected Platform** | Ubuntu Desktop 24.04 LTS (reported) |
| **Vulnerable Component** | `snapd` (`snap-confine`) |
| **Flaw Type** | Race condition + logic error around `/tmp/.snap` handling |
| **Exploitation Requirement** | Local low-privilege access and timing control |
| **Potential Outcome** | Root privilege escalation and arbitrary code execution |

## Affected Products

- Ubuntu Desktop systems using vulnerable `snapd` / `snap-confine` behavior.
- Multi-user systems where local unprivileged accounts are present.
- Environments with limited monitoring of temporary-directory and mount activity.

**The following snapd package versions are vulnerable. Organizations should upgrade immediately to the listed patched releases:**

- Ubuntu 24.04 LTS: snapd versions prior to 2.73+ubuntu24.04.2
- Ubuntu 25.10 LTS: snapd versions prior to 2.73+ubuntu25.10.1
- Ubuntu 26.04 LTS (Dev): snapd versions prior to 2.74.1+ubuntu26.04.1
- Upstream snapd: versions prior to 2.75

## Technical Details

- `systemd-tmpfiles` can clean up `/tmp/.snap` during normal maintenance operations.
- An attacker can race to recreate `/tmp/.snap` with malicious controlled content.
- `snap-confine` subsequently processes/mounts attacker-controlled files as root.
- This behavior can convert local access into full root compromise.
- Exploit reliability depends on local access and precise operation timing.

## Attack Scenario

1. Attacker obtains local low-privilege access (for example via compromised account or breakout scenario).
2. Attacker waits for cleanup of `/tmp/.snap` by `systemd-tmpfiles`.
3. The directory is recreated with malicious content under attacker control.
4. A Snap execution path triggers `snap-confine` processing.
5. `snap-confine` mounts/uses malicious content with root privileges.
6. Attacker gains full root-level control of the host.

## Impact Assessment

=== "Privilege and Execution Impact"
    Successful exploitation can grant full root access and arbitrary command execution on affected hosts.

=== "Security and Persistence Impact"
    Attackers may establish persistence, steal credentials, tamper with logs, and disable defensive tooling.

=== "Enterprise Risk Impact"
    Compromise of a single host can enable broader enterprise movement and complete endpoint trust failure.

## Mitigation Strategies

- Apply official Ubuntu security updates for `snapd` immediately.
- Restrict and audit local user access on sensitive endpoints.
- Monitor `/tmp` and related paths for suspicious recreation or tampering behavior.
- Enable `auditd` and file-integrity monitoring for privileged file and mount operations.
- Alert on anomalous Snap execution patterns and unusual mount activity.

## Resources

!!! info "Open-Source Reporting"
    - [CVE-2026-3888: Ubuntu Desktop 24.04+ vulnerable to Root exploit](https://securityaffairs.com/189614/security/cve-2026-3888-ubuntu-desktop-24-04-vulnerable-to-root-exploit.html)
    - [NVD - CVE-2026-3888](https://nvd.nist.gov/vuln/detail/CVE-2026-3888)
    - [Ubuntu CVE-2026-3888 Bug Lets Attackers Gain Root via systemd Cleanup Timing Exploit](https://thehackernews.com/2026/03/ubuntu-cve-2026-3888-bug-lets-attackers.html)
    - [New Ubuntu Flaw Enables Local Attackers to Gain Root Access - Infosecurity Magazine](https://www.infosecurity-magazine.com/news/ubuntu-flaw-enables-root-access/)
    - [CVE-2026-3888: Important Snap Flaw Enables Local Privilege Escalation to Root | Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2026/03/17/cve-2026-3888-important-snap-flaw-enables-local-privilege-escalation-to-root)

---
*Last Updated: March 26, 2026*