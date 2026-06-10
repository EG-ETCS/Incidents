# RoguePlanet – Microsoft Defender Zero-Day Local Privilege Escalation
![alt text](images/RoguePlanet.png)

**Zero-Day**{.cve-chip} **Privilege Escalation**{.cve-chip} **Race Condition**{.cve-chip} **Microsoft Defender**{.cve-chip}

## Overview

RoguePlanet is a zero-day vulnerability in Microsoft Defender that allows a low-privileged local attacker to escalate privileges to SYSTEM level. The flaw exists in Defender's internal remediation and file-handling workflow, where a race condition (TOCTOU – Time-of-Check to Time-of-Use) can be exploited to manipulate file operations during privileged execution, enabling a SYSTEM shell. No remote exploitation has been confirmed; local access is required.

## Technical Specifications

| Attribute | Details |
|---|---|
| **Vulnerability Name** | RoguePlanet |
| **Vulnerability Type** | Race Condition — TOCTOU (Time-of-Check to Time-of-Use) |
| **Affected Component** | Microsoft Defender remediation engine |
| **Attack Vector** | Local |
| **Authentication** | Low-privileged local user |
| **Complexity** | High (race condition timing required) |
| **User Interaction** | Not Required (after initial access) |
| **Remote Exploitation** | Not confirmed |
| **Exploitation Technique** | Symbolic links / NTFS junction abuse during privileged file operations |
| **Result** | Privileged file overwrite or execution; SYSTEM shell spawning |
| **Patch Status** | Patch pending via MSRC advisory |

## Affected Products

- Microsoft Defender on Windows (all versions where remediation engine performs privileged file operations)
- Enterprise environments relying primarily on Defender as the sole endpoint security solution

## Attack Scenario

1. Attacker gains local access via phishing, malware delivery, or user-assisted execution.
2. Attacker runs the RoguePlanet exploit to trigger a race condition in the Defender remediation engine.
3. Attacker manipulates filesystem state during Defender's privileged file operation using symbolic links or NTFS junctions.
4. Defender performs a privileged operation on an attacker-controlled file path.
5. A SYSTEM-level shell is spawned for the attacker.
6. Attacker disables security tools, dumps credentials, and escalates the attack through lateral movement and persistence.

## Impact

=== "Integrity"

    - Full SYSTEM-level compromise of the Windows host
    - Disablement or bypass of Microsoft Defender and other security controls
    - Potential ransomware deployment following privilege escalation

=== "Confidentiality"

    - Credential dumping via LSASS access at SYSTEM level
    - Access to all files and secrets on the compromised host
    - High risk for enterprise environments relying on Defender for endpoint protection

=== "Availability"

    - Lateral movement across enterprise networks following SYSTEM compromise
    - Disruption of endpoint security tooling through Defender disablement
    - Operational impact from persistence mechanisms installed at SYSTEM level

## Mitigations

### Immediate Actions

- Apply Microsoft security updates as soon as patches are released via MSRC advisories
- Restrict local user access and minimize administrative privileges on endpoints
- Enable Defender Attack Surface Reduction (ASR) rules to limit exploitation surface

### Short-term Measures

- Deploy layered EDR solutions rather than relying on Defender alone
- Restrict execution of unknown or unsigned binaries
- Audit local user accounts and remove unnecessary privileges

### Monitoring & Detection

- Monitor for symbolic link and NTFS junction abuse on endpoints
- Alert on abnormal Defender remediation engine activity or unexpected file operations
- Monitor for SYSTEM process spawning from unusual parent processes
- Detect anomalous LSASS access attempts following local privilege escalation patterns

### Long-term Solutions

- Enforce least-privilege access policies across enterprise endpoints
- Implement privileged access workstations (PAWs) for sensitive operations
- Maintain a defense-in-depth strategy with multiple endpoint security layers

## Resources

!!! info "Open-Source Reporting"
    - [Microsoft Defender RoguePlanet Zero-Day Grants SYSTEM Access on Updated Windows](https://thehackernews.com/2026/06/microsoft-defender-rogueplanet-zero-day.html)
    - [Microsoft Defender 'RoguePlanet' zero-day grants SYSTEM privileges](https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-rogueplanet-zero-day-grants-system-privileges/amp/)
    - [Defender Zero Day Exploit: RoguePlanet Disclosed](https://securityonline.info/defender-zero-day-exploit-rogueplanet/)
    - [New Windows Defender 0-Day Exploit "RoguePlanet" Grants SYSTEM Access to Attackers](https://cybersecuritynews.com/windows-defender-0-day-exploit-rogueplanet/)

---

*Last Updated: June 10, 2026*
