# China-linked Linux Authentication Backdoor Campaign & Long-term Authentication Flow Hijacking Operation
![alt text](images/Hijacking.png)

**Linux Backdoor**{.cve-chip} **Authentication Hijacking**{.cve-chip} **China-Linked Threat**{.cve-chip} **Long-Term Espionage**{.cve-chip}

## Overview

A China-linked threat actor conducted a long-running cyber espionage campaign by embedding malicious functionality into Linux authentication systems, including PAM (Pluggable Authentication Modules) and OpenSSH components.

The attackers also hijacked authentication flows in isolated enterprise environments, allowing them to silently intercept credentials, monitor administrative sessions, and maintain persistent access for up to a decade without detection.

## Technical Specifications

| Attribute | Details |
|---|---|
| **Campaign Type** | Long-term Linux authentication backdoor and flow hijacking operation |
| **Primary Targets** | Linux authentication stack components in enterprise environments |
| **Tampered Components** | PAM modules and OpenSSH authentication routines |
| **Credential Collection** | Captured usernames/passwords at login and logged privileged commands |
| **Authentication Manipulation** | Hooking into login verification flow; potential bypass of MFA/internal controls in some environments |
| **Persistence Characteristics** | In some cases survived OS updates and blended with trusted libraries |
| **Stealth Mechanisms** | No separate malware process required; code operated inside legitimate authentication binaries |
| **Operational Duration** | Reported long-term covert access, potentially up to ~10 years |
| **CVE IDs** | Not specified in referenced reporting |

## Affected Products

- Linux servers using PAM and OpenSSH authentication stacks
- Internal enterprise environments, including segmented or partially isolated networks
- Administrative authentication paths and privileged shell access workflows

## Attack Scenario

1. Attackers gain initial access through an exposed service or upstream compromise.
2. They move laterally into internal network segments.
3. Privilege escalation is performed to reach system/root level.
4. PAM/OpenSSH authentication components are tampered with.
5. Hidden credential interception and command-logging logic is deployed.
6. Login activity and administrator sessions are continuously monitored.
7. Stolen data is exfiltrated over covert channels for long-term espionage.

## Impact

=== "Integrity"

    - Trust in core Linux authentication mechanisms is undermined by binary/library tampering
    - Privileged access controls can be subverted through manipulated authentication flows
    - Long-lived unauthorized access increases risk of systemic infrastructure compromise

=== "Confidentiality"

    - Full visibility into administrator logins, credentials, and sensitive command activity
    - Elevated risk of data exposure across internal systems and segmented environments
    - Credential theft enables secondary intrusions into connected systems and services

=== "Availability"

    - Potential operational disruption during incident response and credential reset campaigns
    - Higher risk of service impact if adversaries leverage privileged persistence destructively
    - Long-term compromise can degrade reliability of security operations and platform governance

## Mitigations

### System Hardening

- Verify integrity of `/etc/pam.d/`, PAM libraries (`/lib/security/`, `/lib64/security/`), and OpenSSH binaries (`sshd`, `ssh`)
- Use signed package repositories only

### Detection & Monitoring

- Enable file integrity monitoring (FIM)
- Audit authentication logs (`auth.log`, `secure`)
- Monitor SSH behavior anomalies
- Deploy Linux EDR solutions

### Identity Security

- Enforce MFA for privileged accounts
- Rotate credentials regularly
- Use short-lived credentials where possible

### Network Controls

- Segment critical systems
- Restrict SSH access to administrative jump hosts
- Monitor east-west traffic inside internal networks

## Resources

!!! info "Open-Source Reporting"
    - [Chinese hackers hijack auth flow, spy on isolated network for a decade](https://www.bleepingcomputer.com/news/security/chinese-hackers-hijack-auth-flow-spy-on-isolated-network-for-a-decade/)
    - [China-Linked Hackers Backdoored Linux Login Software to Hide for Nearly a Decade](https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html)

---

*Last Updated: June 14, 2026*
