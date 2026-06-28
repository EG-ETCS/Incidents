# Cisco Catalyst SD-WAN Zero-Day Exploitation
![alt text](images/SD-WAN.png)

**CVE-2026-20182**{.cve-chip}  
**Authentication Bypass / Privilege Escalation**{.cve-chip}  
**Cisco Catalyst SD-WAN**{.cve-chip}

## Overview
Multiple zero-day vulnerabilities affecting Cisco Catalyst SD-WAN products were reportedly exploited in the wild before fixes were broadly applied. The activity targeted SD-WAN Manager (vManage) and Controller (vSmart) systems to gain administrative access, execute commands with elevated privileges, and maintain persistence inside enterprise environments.

The campaign is associated with exploitation of vulnerabilities including CVE-2026-20182, CVE-2026-20245, and CVE-2026-20127. Attackers reportedly added unauthorized SSH keys, modified NETCONF configurations, escalated privileges toward root access, and established footholds that could enable broader compromise across SD-WAN-managed networks.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **CVE ID** | CVE-2026-20182, CVE-2026-20245, CVE-2026-20127 |
| **Vulnerability Type** | Authentication bypass, privilege escalation, arbitrary command execution |
| **CVSS Score** | CVE-2026-20182: 10.0 (Critical); other related flaws: severe/critical depending on component |
| **Attack Vector** | Network |
| **Authentication** | None for initial authentication bypass in affected scenarios |
| **Complexity** | Low to Medium |
| **User Interaction** | Not Required |
| **Affected Versions** | Cisco Catalyst SD-WAN Controller and Manager across multiple release trains prior to fixed versions; internet-exposed systems at highest risk |

## Affected Products
- Cisco Catalyst SD-WAN Manager (formerly vManage)
- Cisco Catalyst SD-WAN Controller (formerly vSmart)
- On-premises Cisco Catalyst SD-WAN deployments
- Cisco SD-WAN Cloud-Pro deployments
- Cisco SD-WAN Cloud (Cisco Managed) deployments
- Cisco SD-WAN for Government / FedRAMP environments

## Attack Scenario
1. An attacker scans for internet-facing Cisco Catalyst SD-WAN management interfaces and exposed controller services.
2. Using an authentication bypass flaw, the attacker gains unauthorized administrative or highly privileged access to affected vManage or vSmart systems.
3. The attacker executes commands, modifies SD-WAN configuration via NETCONF or related interfaces, and attempts privilege escalation to root.
4. Persistence is established by adding unauthorized SSH keys or other backdoor mechanisms to retain long-term access.
5. From the compromised SD-WAN control plane, the attacker pivots across the SD-WAN fabric to monitor traffic, manipulate policy, or compromise downstream branch infrastructure.

## Impact Assessment

### Integrity
- Attackers can alter SD-WAN policies, control-plane trust relationships, and network configurations.
- Unauthorized SSH keys and NETCONF changes can establish persistent administrative control.
- Compromise of vManage or vSmart can undermine the integrity of the broader SD-WAN fabric.

### Confidentiality
- A compromised SD-WAN environment may expose administrative credentials, network topology, and configuration secrets.
- Attackers may gain visibility into traffic flows and potentially intercept or monitor sensitive enterprise communications.
- Follow-on access may facilitate credential theft and intelligence collection across connected sites.

### Availability
- Malicious configuration changes can disrupt branch connectivity and centralized management operations.
- Control-plane compromise may cause policy misrouting, service outages, or degraded network performance.
- Incident response and recovery may require controller isolation, credential rotation, and emergency change management.

## Mitigation Strategies

### Immediate Actions
- Apply Cisco security patches and move affected systems to fixed releases immediately.
- Restrict exposure of SD-WAN management interfaces from the public internet.
- Rotate administrative credentials and SSH keys if compromise is suspected.

### Short-term Measures
- Enable MFA for administrative access to SD-WAN management systems.
- Segment management networks and limit access to trusted administration hosts.
- Review controller configurations and remove unauthorized SSH keys, users, or persistence artifacts.

### Monitoring & Detection
- Audit logs for unauthorized logins, suspicious privilege changes, and abnormal NETCONF modifications.
- Hunt for Cisco Talos indicators of compromise and evidence of persistence on vManage and vSmart nodes.
- Review recent configuration changes, control-plane behavior, and unexpected administrative actions across the SD-WAN environment.

## Resources and References

!!! info "Official Documentation"
    - [SecurityWeek - Cisco SD-WAN Zero-Day Exploited Months Before Patching](https://www.securityweek.com/cisco-sd-wan-zero-day-exploited-months-before-patching/)
    - [Help Net Security - Cisco SD-WAN 0-day exploited, no patch available (CVE-2026-20245)](https://www.helpnetsecurity.com/2026/06/05/cisco-sd-wan-cve-2026-20245-0-day-exploited/)
    - [Canadian Centre for Cyber Security Advisory AL26-012](https://www.cyber.gc.ca/en/alerts-advisories/al26-012-critical-vulnerability-affecting-cisco-catalyst-sd-wan-cve-2026-20182)
    - [Cisco - Remediate Catalyst SD-WAN Security Advisory](https://www.cisco.com/c/en/us/support/docs/routers/sd-wan/226014-remediate-catalyst-sd-wan-security.html)

***

*Last Updated: June 25, 2026*