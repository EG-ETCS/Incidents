# Linux Kernel nf_tables One-Character Privilege Escalation Vulnerability
![alt text](images/Kernel.png)

**CVE-2026-23111**{.cve-chip} **Privilege Escalation**{.cve-chip} **Use-After-Free**{.cve-chip} **Container Escape**{.cve-chip}

## Overview

A critical vulnerability in the Linux kernel's nf_tables subsystem allows a low-privileged local attacker to escalate privileges to root due to a logic error caused by a single incorrect character in the kernel code. A logic inversion bug introduced by an erroneous `!` operator triggers a Use-After-Free (UAF) memory condition, enabling arbitrary code execution in kernel space. The flaw can also enable container escape in certain environments. Public proof-of-concept (PoC) exploit code is available, significantly increasing exploitation risk.

## Technical Specifications

| Attribute | Details |
|---|---|
| **CVE ID** | CVE-2026-23111 |
| **Vulnerability Type** | Use-After-Free (CWE-416) / Logic Error |
| **Affected Subsystem** | Linux Kernel — Netfilter nf_tables framework |
| **Attack Vector** | Local |
| **Authentication** | Low-privileged user |
| **Complexity** | Low |
| **User Interaction** | Not Required |
| **Impact** | Privilege escalation to root, container escape |
| **PoC Available** | Yes — publicly released |
| **Prerequisite** | nf_tables and unprivileged user namespaces enabled |
| **Confirmed Affected** | Debian Bookworm, Debian Trixie, Ubuntu 22.04 LTS, Ubuntu 24.04 LTS |

## Affected Products

- Linux kernel versions with the nf_tables logic inversion bug
- Debian Bookworm
- Debian Trixie
- Ubuntu 22.04 LTS
- Ubuntu 24.04 LTS
- Any Linux distribution with nf_tables and unprivileged user namespaces enabled

## Attack Scenario

1. Attacker gains initial low-privileged access via stolen credentials, phishing, malware, or a compromised service.
2. Attacker executes the public PoC exploit locally on the target Linux system.
3. The exploit triggers the Use-After-Free condition in the nf_tables kernel subsystem.
4. Attacker gains root-level privileges on the system.
5. In containerized environments, the attacker may escape the container and compromise the host operating system.

## Impact

=== "Integrity"

    - Full system compromise through root-level arbitrary code execution
    - Deployment of ransomware or persistent malware after privilege escalation
    - Data tampering or destruction with unrestricted kernel-level access

=== "Confidentiality"

    - Theft of sensitive data accessible only to root or the kernel
    - Lateral movement inside enterprise environments following host compromise
    - Exfiltration of credentials, secrets, and configuration data

=== "Availability"

    - Security control bypass, neutralizing host-based defenses
    - Container escape enabling cascading compromise of the host and other workloads
    - Potential for service disruption or system instability from kernel exploitation

## Mitigations

### Immediate Actions

- Immediately update affected Linux kernels with vendor-supplied security patches
- Reboot systems after patching to load the updated kernel
- Disable unprivileged user namespaces if not required:
  ```
  sudo sysctl -w kernel.unprivileged_userns_clone=0
  ```
- Restrict local shell access for untrusted users

### Short-term Measures

- Apply AppArmor or SELinux mandatory access control policies
- Minimize container privileges and avoid running containers as privileged users
- Audit systems for evidence of prior exploitation attempts

### Monitoring & Detection

- Monitor systems for suspicious namespace creation or unusual kernel-level activity
- Detect unexpected privilege escalation events in audit logs
- Alert on anomalous use of nf_tables-related system calls by low-privileged processes

## Resources

!!! info "Open-Source Reporting"
    - [One-Character Linux Kernel Flaw Enables Local Root Access, Exploits Now Public](https://thehackernews.com/2026/06/one-character-linux-kernel-flaw-enables.html)
    - [Reproducing CVE-2026-23111: How One Character Can Change Everything](https://fuzzinglabs.com/repro-cve-2026-23111/)
    - [A single character could be enough to let hackers crack your Linux kernel | TechRadar](https://www.techradar.com/pro/security/a-single-character-could-be-enough-to-let-hackers-crack-your-linux-kernel)

---

*Last Updated: June 10, 2026*
