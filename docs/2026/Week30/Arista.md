# Arista VeloCloud Orchestrator Zero-Day (CVE-2026-16812)
![alt text](images/Arista.png)

**CVE-2026-16812**{.cve-chip} **Unauthenticated RCE**{.cve-chip} **OS Command Injection**{.cve-chip} **SD-WAN Infrastructure Risk**{.cve-chip} **Active Exploitation**{.cve-chip}

## Overview

Arista Networks released security updates for CVE-2026-16812, a critical unauthenticated operating system command injection vulnerability affecting on-premises Arista VeloCloud Orchestrator (VCO) deployments.

The flaw is reported as actively exploited in the wild and could enable remote takeover of central SD-WAN management infrastructure, creating high downstream risk across connected enterprise environments.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **CVE ID** | CVE-2026-16812 |
| **CVSS Score** | 10.0 (Critical) |
| **Vulnerability Type** | OS Command Injection (CWE-78) |
| **Authentication Required** | None |
| **User Interaction** | None |
| **Attack Vector** | Network (Remote) |
| **Affected Product** | Arista VeloCloud Orchestrator (On-Premises) |
| **Fixed Versions** | 5.2.3.14, 6.1.3.4, 6.4.2.4, 7.0.0.1 |
| **Exploit Status** | Active exploitation observed in the wild |
| **Disclosure Constraints** | Detailed vulnerable component and full exploit chain not publicly disclosed during active exploitation period |

Under vulnerable conditions, specially crafted unauthenticated requests can inject and execute OS-level commands on the orchestrator host with the privileges of the VCO service context.

## Affected Products

- On-premises Arista VeloCloud Orchestrator instances on vulnerable software branches
- Enterprise SD-WAN management planes administered by affected VCO servers
- Branch and edge environments relying on orchestrator-pushed policies and routing
- Security and operations workflows dependent on trusted orchestrator integrity

## Attack Scenario

1. Attackers scan for Internet-exposed Arista VeloCloud Orchestrator instances.
2. A vulnerable on-premises VCO deployment is identified.
3. The attacker sends a crafted unauthenticated request to trigger command injection.
4. Arbitrary OS commands execute on the orchestrator server.
5. Persistence is established and attacker control over the management host is expanded.
6. Administrative credentials and orchestration data are accessed or stolen.
7. SD-WAN policy/routing changes enable lateral movement and broader enterprise impact.

## Impact Assessment

=== "Integrity"

    - Full orchestrator compromise can enable unauthorized SD-WAN policy and routing modifications
    - Attacker control over central management may propagate malicious configuration at scale
    - Trust in orchestration workflows and administrative control paths is materially degraded

=== "Confidentiality"

    - Exposure of administrator credentials, orchestration metadata, and network configuration details
    - Potential interception/redirection opportunities through manipulated routing or policy logic
    - Compromised management infrastructure may reveal sensitive branch connectivity topology

=== "Availability"

    - Service disruption can occur through malicious configuration, process tampering, or ransomware deployment
    - Branch office connectivity and application reachability may be degraded or interrupted
    - Recovery actions (containment, credential rotation, rebuilds) can impact operational continuity

## Mitigation Strategies

### Immediate Actions

- Upgrade immediately to patched versions: 5.2.3.14, 6.1.3.4, 6.4.2.4, or 7.0.0.1 as applicable
- Remove direct Internet exposure of VCO management interfaces wherever possible
- Restrict management access using firewalls, VPN enforcement, and strict IP allowlisting

### Short-term Measures

- Enforce MFA for all administrator accounts with VCO access
- Rotate privileged credentials if compromise is suspected or cannot be ruled out
- Validate SD-WAN policy/routing baselines and review recent configuration changes for anomalies

### Monitoring & Detection

- Monitor VCO and host logs for suspicious HTTP requests and abnormal command execution patterns
- Alert on unusual administrative actions, account behavior, and unexpected orchestration events
- Track unauthorized changes in SD-WAN configuration, routing, and control-plane access

### Long-term Solutions

- Segment management-plane infrastructure from untrusted networks with layered access controls
- Establish routine vulnerability management and rapid patching SLAs for SD-WAN control systems
- Implement continuous integrity monitoring and incident playbooks for orchestrator compromise scenarios

## Resources and References

!!! info "Public Reporting"
    - [Arista patches VeloCloud Orchestrator zero-day exploited in attacks](https://www.bleepingcomputer.com/news/security/arista-patches-velocloud-orchestrator-zero-day-exploited-in-attacks/)

---

*Last Updated: July 28, 2026*
