# PinTheft Linux Privilege Escalation Vulnerability

**CVE-2026-31635**{.cve-chip} **Linux Kernel LPE**{.cve-chip} **RDS Subsystem**{.cve-chip} **Public Exploit**{.cve-chip}

## Overview

PinTheft is a Linux kernel local privilege escalation (LPE) vulnerability affecting the RDS (Reliable Datagram Sockets) subsystem. The flaw exists in the `rds_message_zcopy_from_user()` function's zerocopy send path, where improper handling of pinned page references triggers a double-free condition. Attackers abuse the interaction between RDS zerocopy networking and `io_uring` fixed buffers to achieve page-cache overwrite primitives, enabling arbitrary file or memory modification and eventual root privilege escalation. Public exploit code is available, materially increasing the risk of active in-the-wild exploitation.

## Technical Specifications

| Attribute | Details |
|---|---|
| **CVE** | CVE-2026-31635 |
| **Vulnerability Name** | PinTheft |
| **Affected Component** | Linux kernel — RDS (Reliable Datagram Sockets) subsystem |
| **Vulnerable Function** | `rds_message_zcopy_from_user()` |
| **Root Cause** | Improper page reference handling during zerocopy operations → double-free condition |
| **Exploit Technique** | RDS zerocopy + `io_uring` fixed buffer interaction → page-cache overwrite primitive → root LPE |
| **Access Required** | Local unprivileged user |
| **Public Exploit** | Yes — PoC available; noted to target Arch Linux |
| **Impact** | Full root privilege escalation |

## Affected Products

- **Linux kernel** versions containing the vulnerable RDS zerocopy send path (patch not yet universally applied across all distributions)
- Notably demonstrated on **Arch Linux**; other distributions shipping the affected kernel versions are also at risk
- Environments with `io_uring` and RDS enabled (many default Linux configurations) are in scope

## :material-file-search: Attack Scenario

1. Attacker gains local low-privileged access to the target system — via SSH with a compromised account, a vulnerable application, container access, or a shared hosting account
2. Attacker executes the publicly available PinTheft exploit locally on the system
3. The exploit triggers kernel memory corruption via the RDS subsystem's `rds_message_zcopy_from_user()` function, inducing a double-free condition in pinned page handling
4. The attacker leverages the interaction between RDS zerocopy and `io_uring` fixed buffers to establish a page-cache overwrite primitive, enabling modification of privileged files or kernel memory structures
5. Privilege escalation to root is achieved, granting full system control — enabling rootkit installation, credential access, security tool bypass, and further lateral movement

## Impact

=== "System Impact"

    - Full root compromise of the affected Linux system
    - Installation of rootkits, persistence mechanisms, or kernel backdoors that survive reboots
    - Bypass of security monitoring tools including EDR, audit frameworks, and integrity checkers running in user space
    - Access to all sensitive files, credentials, secrets, and private keys stored on the system

=== "Infrastructure and Container Risk"

    - Potential container escape — a low-privileged process inside a container that can reach the vulnerable kernel path may be able to break container isolation and compromise the host
    - Lateral movement across infrastructure using credentials and keys extracted after root access is achieved
    - Compromise of CI/CD runners, build servers, or shared development systems may propagate access to broader pipeline infrastructure

=== "Exploitation Risk"

    - Public proof-of-concept code is available, lowering the technical barrier for exploitation significantly
    - Any threat actor — including opportunistic attackers and ransomware groups — with local access to an unpatched system can achieve root with minimal effort
    - Environments relying on container isolation, shared hosting, or multi-tenant Linux infrastructure face elevated risk from tenant-level initial access escalating to host compromise

## :material-shield-check: Mitigations

### Immediate Priority

- **Update affected Linux kernels immediately** to versions containing the upstream fix for CVE-2026-31635; apply vendor security patches from your distribution (Arch, Debian, Ubuntu, RHEL, etc.) and **reboot systems** after patching — the fix is only active post-reboot
- **Disable or unload the RDS kernel module** if it is not actively required: `modprobe -r rds` and add `blacklist rds` to `/etc/modprobe.d/` to prevent reloading; this eliminates the attack surface entirely on systems that do not use RDS

### Defense in Depth

- **Limit `io_uring` usage where possible** — restrict or disable `io_uring` via sysctl (`kernel.io_uring_disabled = 1`) on systems that do not require it; this severs the exploit's required interaction between RDS and `io_uring` fixed buffers
- **Enable AppArmor or SELinux** mandatory access control policies to constrain what unprivileged processes and containers can access, potentially disrupting exploit chains even on unpatched systems
- **Restrict local shell access** — limit which users and service accounts can obtain interactive shell sessions on sensitive systems; reduce the pool of identities that could trigger the exploit

### Monitoring and Hardening

- **Monitor for suspicious privilege escalation activity** — alert on unexpected UID transitions to root (0), unusual `io_uring` syscall patterns from unprivileged processes, and RDS socket creation from non-standard processes
- **Harden container isolation policies** — ensure containers run with the minimum required capabilities; drop `CAP_NET_RAW` and restrict kernel namespace access where the workload does not require them
- **Audit shared and multi-tenant environments** for unpatched kernel versions; prioritize patching on systems with broad user access (jump hosts, CI/CD runners, shared development servers)

## :material-book-open-variant: Resources

!!! info "Open-Source Reporting"

    - [PinTheft: Another Linux Privilege Escalation, Another Working Exploit, This Time Targeting Arch — Hackread](https://hackread.com/pintheft-linux-privilege-escalation-working-exploit-arch/)
    - [Exploit Released for New PinTheft Arch Linux Root Escalation Flaw — BleepingComputer](https://www.bleepingcomputer.com/news/security/exploit-released-for-new-pintheft-arch-linux-root-escalation-flaw/)
    - [DirtyDecrypt PoC Released for Linux Kernel CVE-2026-31635 LPE Vulnerability — Hackread](https://hackread.com/dirtydecrypt-poc-linux-kernel-cve-2026-31635-lpe/)
    - [oss-security: PinTheft Linux LPE — OpenWall OSS-Security](https://www.openwall.com/lists/oss-security/2026/05/pintheft-linux-lpe)
    - [oss-sec: Re: PinTheft Linux LPE — OpenWall OSS-Security](https://www.openwall.com/lists/oss-security/2026/05/re-pintheft-linux-lpe)
