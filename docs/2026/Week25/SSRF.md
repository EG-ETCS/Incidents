# Cisco Unified CM SSRF Vulnerability – CVE-2026-20230
![alt text](images/SSRF.png)

**CVE-2026-20230**{.cve-chip}  
**Server-Side Request Forgery (SSRF)**{.cve-chip}  
**Cisco Unified CM / Root Compromise**{.cve-chip}

## Overview
CVE-2026-20230 is a critical server-side request forgery vulnerability affecting Cisco Unified Communications Manager (Unified CM) and Unified CM Session Management Edition (SME). The flaw allows unauthenticated remote attackers to send crafted HTTP requests that may result in arbitrary file creation on the underlying operating system and possible root-level compromise.

The issue exists in the WebDialer component and is especially relevant for environments where the service is enabled. Public reporting indicates strong exploitation interest, and proof-of-concept exploit code is available, increasing the risk to exposed enterprise voice infrastructure.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **CVE ID** | CVE-2026-20230 |
| **Vulnerability Type** | Server-Side Request Forgery (SSRF) leading to arbitrary file creation |
| **CVSS Score** | 8.6 (Critical operational impact) |
| **Attack Vector** | Network |
| **Authentication** | None |
| **Complexity** | Low |
| **User Interaction** | Not Required |
| **Affected Versions** | Cisco Unified CM Release 14 prior to 14SU6; Release 15 prior to 15SU5 or interim COP patch; same exposure pattern for Unified CM SME when WebDialer is enabled |

## Affected Products
- Cisco Unified Communications Manager (Unified CM)
- Cisco Unified Communications Manager Session Management Edition (Unified CM SME)
- Release 14 deployments earlier than 14SU6 with WebDialer enabled
- Release 15 deployments earlier than 15SU5 with WebDialer enabled
- Voice environments exposing Unified CM services to untrusted networks

## Attack Scenario
1. An attacker scans for internet-facing Cisco Unified CM or Unified CM SME servers.
2. The target system has the WebDialer service enabled.
3. The attacker sends crafted HTTP requests to exploit the SSRF condition in WebDialer.
4. The vulnerability is abused to force unintended internal requests and write arbitrary files to the underlying Linux-based operating system.
5. The attacker uses the file-write capability to escalate privileges and gain root access.
6. The compromised server can then be used for persistence, credential theft, call interception, service abuse, or lateral movement into adjacent enterprise systems.

## Impact Assessment

### Integrity
- Attackers may create arbitrary files and alter the behavior of the affected system.
- Root-level access can allow full administrative control over the communications platform.
- A compromised Unified CM server may be modified for persistence or malicious operational changes.

### Confidentiality
- Enterprise communication systems may be exposed to unauthorized access.
- Attackers may steal credentials, configuration data, and sensitive telephony-related information.
- Successful compromise may create opportunities for call monitoring or interception depending on the environment.

### Availability
- Exploitation can destabilize communications services or supporting infrastructure.
- Malicious changes may interrupt voice operations and administrative access.
- Compromise of central voice-management systems can contribute to wider service disruption and recovery complexity.

## Mitigation Strategies

### Immediate Actions
- Apply Cisco security patches immediately.
- Upgrade Release 14 systems to 14SU6 and apply the appropriate remediation for Release 15 systems, including the interim COP patch where needed.
- Disable WebDialer if it is not operationally required.

### Short-term Measures
- Restrict external access to Unified CM administrative and application interfaces.
- Segment voice infrastructure from sensitive internal systems.
- Rotate credentials and review privileged access if compromise is suspected.

### Monitoring & Detection
- Monitor logs for suspicious HTTP requests targeting WebDialer.
- Investigate unexpected file creation or unauthorized changes on the underlying operating system.
- Perform IOC hunting, configuration review, and continuous monitoring for signs of persistence or lateral movement.

## Resources and References

!!! info "Official Documentation"
    - [Security Affairs - Cisco Unified CM Flaw CVE-2026-20230 Actively Exploited in the Wild](https://securityaffairs.com/194153/uncategorized/cisco-unified-cm-flaw-cve-2026-20230-actively-exploited-in-the-wild.html)
    - [The Hacker News - Cisco Patches CVE-2026-20230 in Unified CM as Exploit Code Goes Public](https://thehackernews.com/2026/06/cisco-patches-cve-2026-20230-in-unified.html)
    - [Canadian Centre for Cyber Security Advisory AV26-547](https://www.cyber.gc.ca/en/alerts-advisories/cisco-security-advisory-av26-547)

***

*Last Updated: June 25, 2026*