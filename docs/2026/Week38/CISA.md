# Three Actively Exploited Linux Kernel Vulnerabilities Added to CISA KEV
![alt text](images/CISA.png)

**CISA KEV**{.cve-chip} **Linux Kernel**{.cve-chip} **Active Exploitation**{.cve-chip} **CVE-2025-39964**{.cve-chip} **CVE-2026-53266**{.cve-chip} **CVE-2025-39682**{.cve-chip}

## Overview

CISA warned that threat actors are actively exploiting three Linux kernel vulnerabilities and added them to the Known Exploited Vulnerabilities (KEV) Catalog: **CVE-2025-39964**, **CVE-2026-53266**, and **CVE-2025-39682**.

CISA assigned all three its highest remediation priority for U.S. federal civilian agencies, requiring updates/mitigations and forensic triage by **September 21, 2026**. Public reporting does not disclose victim organizations, detailed exploitation chains, or named threat actors.

## Technical Details

### CVE-2025-39964 - AF_ALG Race Condition

- Component: Linux kernel AF_ALG cryptographic socket interface.
- Root cause: race condition in concurrent write operations that can corrupt per-socket state.
- Potential impact: system instability, altered cryptographic behavior, and privilege-escalation paths.
- Research context: STAR Labs reported the issue and demonstrated privilege escalation and container escape in kernelCTF context.
- Historical note: publicly described as present for roughly 14 years prior to discovery.

### CVE-2026-53266 - ebtables SNAT Out-of-Bounds Write

- Component: Linux kernel ebtables SNAT handling.
- Root cause: ARP-address rewrite path can write out of bounds under specific writable-memory assumptions.
- Potential impact: memory corruption and possible local privilege escalation.
- Exploit status: public reporting indicates known exploit availability.

### CVE-2025-39682 - Linux kTLS Receive-Path Logic Flaw

- Component: Linux kernel TLS (kTLS) receive path.
- Root cause: mishandling of deferred zero-length TLS records may allow record-type processing confusion.
- Relevant condition: systems/services using kTLS.
- Exploit status: public reporting notes publicly available exploit material.

### Exploitation and Attribution

- CISA marks all three CVEs as actively exploited.
- No public attribution to a named actor, country, malware family, or campaign in CISA's published notice.
- No public ransomware-association designation for these specific CVEs at this time.
- Forensic triage is explicitly emphasized in CISA remediation guidance.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Catalog Status** | Listed in CISA KEV |
| **CVEs** | CVE-2025-39964, CVE-2026-53266, CVE-2025-39682 |
| **Primary Risk Class** | Linux-kernel memory/race/logic weaknesses with local escalation potential |
| **Environment Risk** | Servers, cloud hosts, container nodes, Linux appliances |
| **Exploit Context** | Active exploitation confirmed by CISA; limited public operational details |
| **Federal Directive Context** | Prioritized remediation plus forensic triage deadline (September 21, 2026) |

## Affected Products

- Linux systems running vulnerable kernel versions or affected distribution builds.
- Container hosts and shared Linux infrastructure where local privilege boundaries are critical.
- Systems using AF_ALG, ebtables SNAT paths, or kTLS-enabled workloads (as applicable).

## Attack Scenario

### Scenario A - AF_ALG Privilege Escalation / Container Escape

1. Attacker gains initial low-privileged code execution on a Linux host/container.
2. Race condition is triggered in AF_ALG write handling.
3. Memory/state corruption is leveraged for escalation or escape.
4. Attacker executes post-compromise actions with elevated privileges.

### Scenario B - ebtables SNAT Memory Modification

1. Attacker obtains local execution foothold.
2. Crafted packet/rule interaction targets SNAT rewrite logic.
3. Out-of-bounds write condition is abused toward privilege escalation.

### Scenario C - kTLS Record Processing Abuse

1. Attacker identifies reachable kTLS-enabled processing context.
2. Malformed/edge-case TLS record sequence is delivered.
3. Receive-path logic confusion creates unsafe state handling.
4. Follow-on exploitation attempts depend on system conditions and access context.

## Impact Assessment

=== "Confirmed Impact"

    - CISA confirms active exploitation of all three vulnerabilities
    - Public research demonstrates serious escalation potential for CVE-2025-39964 in lab/CTF context
    - Public exploit availability has been reported for CVE-2026-53266 and CVE-2025-39682

=== "Potential Impact"

    - Local privilege escalation and possible root-level compromise
    - Container escape risk in affected host/container environments
    - Service instability, crashes, or security-boundary bypass conditions
    - Broader cloud and infrastructure-host exposure depending on kernel deployment footprint

=== "Criticality"

    - **Critical** due to active exploitation status in KEV and high-value impact paths in Linux infrastructure

## Mitigation Strategies

### Identify and Prioritize Affected Assets

- Inventory Linux servers, cloud instances, container nodes, and Linux-based appliances.
- Map kernel versions and distribution patch/advisory status for each CVE.
- Prioritize internet-facing, privileged, and multi-tenant/shared systems.

### Apply Vendor Patches and Reboot Safely

- Apply distribution/vendor security updates for all three CVEs.
- Follow kernel-update operational guidance, including required host reboot windows.
- Verify patched kernels are actively running after maintenance.

### Perform Forensic Triage

- Review authentication, sudo, audit, kernel, container-runtime, orchestration, and network telemetry for exploitation indicators.
- Assess for unusual namespace/process activity, privilege transitions, and suspicious local execution chains.
- Preserve evidence and investigate before broad rebuild where compromise is suspected.

### Reduce Local Attack Surface

- Minimize unnecessary shell access and privileged workload operations.
- Restrict container runtime administration and privileged pod creation.
- Enforce seccomp, AppArmor/SELinux, capability reduction, and least privilege.
- Limit ebtables/netfilter administrative access to authorized operators only.

### Harden Exposed Services

- Patch kTLS-relevant workloads urgently where applicable.
- Segment critical workloads and apply strong service hardening controls.
- For appliances/embedded Linux platforms, follow OEM advisories and isolate unpatchable assets.

### Recovery and Credential Hygiene

- If exploitation evidence exists, rebuild from trusted baselines rather than patch-only response.
- Rotate credentials, tokens, API keys, certificates, and secrets accessible to compromised hosts.
- Review adjacent systems for lateral movement and follow-on persistence.

## Resources and References

!!! info "Public Reporting"
    - [CISA alerts of active exploitation of three Linux kernel flaws](https://www.bleepingcomputer.com/news/security/cisa-alerts-of-active-exploitation-of-three-linux-kernel-flaws/)

---

*Last Updated: September 22, 2026*
