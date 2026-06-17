# FortiSandbox Critical Vulnerabilities Actively Exploited
![alt text](images/FortiSandbox.png)

**CVE-2026-39813**{.cve-chip} **CVE-2026-39808**{.cve-chip} **CVE-2026-25089**{.cve-chip} **Authentication Bypass**{.cve-chip} **Active Exploitation**{.cve-chip} **Remote Code Execution**{.cve-chip}

## Overview

Multiple critical vulnerabilities affecting Fortinet FortiSandbox are being actively exploited in the wild. The flaws allow unauthenticated attackers to bypass authentication and execute arbitrary OS commands remotely through crafted HTTP requests targeting vulnerable JRPC/API interfaces. Successful exploitation may allow attackers to compromise malware analysis systems, manipulate detection verdicts, and gain access to broader enterprise environments through FortiSandbox's Security Fabric integrations.

## Technical Specifications

| Attribute | Details |
|---|---|
| **CVE IDs** | CVE-2026-39813, CVE-2026-39808, CVE-2026-25089 |
| **CVSS Score** | 9.8 (Critical) |
| **Vulnerability Types** | Path Traversal (auth bypass), OS Command Injection, Pre-authentication OS Command Injection |
| **Affected Product** | Fortinet FortiSandbox |
| **Affected Versions** | FortiSandbox 4.4.0–4.4.8, FortiSandbox 5.0.0–5.0.5 |
| **Fixed Versions** | FortiSandbox 4.4.9+, FortiSandbox 5.0.6+ |
| **Attack Vector** | Network (internet-facing management/API interfaces) |
| **Authentication Required** | None |
| **Exploitation Status** | Actively exploited in the wild |
| **Exploitation Method** | Specially crafted HTTP requests to JRPC/API interfaces |

## Affected Products

- Fortinet FortiSandbox 4.4.0 through 4.4.8
- Fortinet FortiSandbox 5.0.0 through 5.0.5
- Enterprise environments with internet-exposed FortiSandbox management interfaces
- Security Fabric deployments where FortiSandbox integrates with other Fortinet products

## Attack Scenario

1. Attacker scans the internet for exposed FortiSandbox management and API interfaces.
2. Using CVE-2026-39813, crafted HTTP requests exploit a path traversal flaw to bypass authentication entirely.
3. Using CVE-2026-39808 or CVE-2026-25089, the attacker injects malicious OS commands via the JRPC/API interface to achieve remote shell access without valid credentials.
4. After gaining access, the attacker may manipulate malware verdicts or disable detections to allow malware through the sandbox undetected.
5. The attacker moves laterally inside the enterprise network, leveraging FortiSandbox's Security Fabric integrations to reach connected systems.
6. Ransomware is deployed, persistence is established, and sensitive data is exfiltrated from the compromised environment.

## Impact

=== "Integrity"

    - Full compromise of FortiSandbox appliances with remote command execution as an unauthenticated attacker
    - Ability to manipulate malware analysis verdicts and disable threat detections
    - Lateral movement through Security Fabric integrations into broader enterprise security infrastructure

=== "Confidentiality"

    - Unauthorized access to malware analysis results, verdicts, and submitted file data
    - Data theft from enterprise environments reached through compromised security appliances
    - Exposure of Security Fabric configuration and integrated product credentials

=== "Availability"

    - Operational disruption from ransomware deployment following lateral movement
    - Disabling of malware detection capabilities affecting enterprise security posture
    - Potential impact to all Fortinet Security Fabric-connected products if the appliance is used as a pivot point

## Mitigations

### Immediate Actions

- Immediately upgrade to FortiSandbox **4.4.9+** or **5.0.6+**
- Restrict access to FortiSandbox management and API interfaces via firewall rules
- Do not expose FortiSandbox systems directly to the internet

### Short-term Measures

- Apply network segmentation to isolate security appliances from general IT networks
- Conduct threat hunting for indicators of compromise (IOCs) on potentially affected systems
- Review Security Fabric integrations for suspicious behavior or unauthorized configuration changes

### Monitoring & Detection

- Monitor logs for suspicious or malformed HTTP requests targeting JRPC/API endpoints
- Alert on unexpected command execution or unusual process spawning from FortiSandbox processes
- Review authentication logs for anomalous access patterns or bypass indicators

### Long-term Solutions

- Enforce management-plane access restrictions across all Fortinet appliances as a baseline hardening standard
- Integrate FortiSandbox logs into a centralized SIEM for continuous monitoring
- Maintain a proactive patch management process for security appliances, treating them as high-priority targets

## Resources

!!! info "Open-Source Reporting"
    - [Three critical Fortinet sandbox bugs splattered by unknown attackers | The Register](https://www.theregister.com/security/2026/06/16/three-critical-fortinet-sandbox-bugs-splattered-by-unknown-attackers/5256461)
    - [Three critical FortiSandbox bugs rated 9.8 actively exploited | SC Media](https://www.scworld.com/news/three-critical-fortisandbox-bugs-rated-98-actively-exploited)

---

*Last Updated: June 17, 2026*
