# Juniper Networks PTX Series Router Critical Vulnerability (CVE-2026-21902)
![alt text](images/Juniper.png)

**CVE-2026-21902**{.cve-chip}  **Remote Code Execution**{.cve-chip}  **Unauthenticated**{.cve-chip}  **Root Access**{.cve-chip}

## Overview
A critical vulnerability in Juniper Networks Junos OS Evolved on PTX Series routers allows remote, unauthenticated attackers to execute arbitrary code as root. The issue stems from improper permission assignment in the On-Box Anomaly Detection framework, where a privileged internal service is mistakenly exposed to external networks and enabled by default.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **CVE ID** | CVE-2026-21902 |
| **Root Cause** | Incorrect permission assignment (CWE-732) |
| **CVSS Score** | 9.3(Critical) |
| **Affected Component** | On-Box Anomaly Detection framework service |
| **Access Vector** | Network (Remote), no authentication required |
| **Privilege Gained** | Root-level code execution |
| **Affected Versions** | Junos OS Evolved on PTX before 25.4R1-S1-EVO and 25.4R2-EVO |
| **Not Affected** | Standard Junos OS (non-Evolved) and non-exposed older Evolved versions |
| **Exploitation Status** | No known in-the-wild exploitation at disclosure time |

## Affected Products
- Juniper PTX Series routers running vulnerable Junos OS Evolved builds
- Environments where the On-Box Anomaly Detection service is externally reachable
- Core routing infrastructures in ISP, telecom, and enterprise networks
- Status: Critical patch available; urgent remediation recommended

## Technical Details

### Vulnerability Mechanics
- The flaw is caused by improper permission assignment in the On-Box Anomaly Detection framework.
- A privileged service intended for internal use is exposed externally by mistake.
- The service runs with elevated privileges and can process attacker-controlled requests.

### Exposure and Trigger Conditions
- Service is enabled by default in affected releases.
- If reachable over network interfaces, no authentication is needed to interact with it.
- Crafted requests can trigger arbitrary command/code execution under root privileges.

### Security Boundary Failure
- Internal-only service trust assumptions are broken by external exposure.
- Root-context execution path amplifies impact from edge exposure to full device compromise.

## Attack Scenario
1. **Reconnaissance**:
    - Attacker identifies reachable PTX routers running vulnerable Junos OS Evolved versions.

2. **Unauthenticated Access**:
    - Attacker connects directly to the exposed On-Box Anomaly Detection service.

3. **Exploit Delivery**:
    - Crafted network requests are sent to exploit the permission/privilege flaw.

4. **Code Execution as Root**:
    - Arbitrary commands execute with root privileges on the router.

5. **Post-Compromise Control**:
    - Attacker can maintain persistence, alter routing behavior, and use the router as a network pivot.

## Impact Assessment

=== "Integrity"
    * Full root-level takeover of PTX routing infrastructure
    * Unauthorized route/policy modifications and traffic redirection
    * Potential manipulation of network control-plane behavior

=== "Confidentiality"
    * Ability to intercept, inspect, or mirror sensitive network traffic
    * Increased risk of data exposure across transiting links
    * Potential foothold for broader network reconnaissance

=== "Availability"
    * Service disruption or outages from malicious router reconfiguration
    * Elevated operational risk for ISPs, telcos, and large enterprises
    * Potential cascading impact across dependent branch/cloud connectivity

## Mitigation Strategies

### Patch Management
- Upgrade Junos OS Evolved to fixed releases: 25.4R1-S1-EVO, 25.4R2-EVO, or 26.2R1-EVO+
- Prioritize externally reachable PTX systems for emergency patching

### Access Restrictions
- Apply ACLs/firewall controls to block external access to the vulnerable service
- Limit management/service-plane exposure to trusted internal administration networks

### Temporary Risk Reduction
- Disable the anomaly framework service until patching is complete using:

```bash
request pfe anomalies disable
```

### Validation and Monitoring
- Verify service exposure from external vantage points after mitigation
- Monitor router logs and configuration history for unexpected changes
- Hunt for signs of unauthorized root-level activity or persistence artifacts

## Resources and References

!!! info "Open-Source Reporting"
    - [Juniper issues emergency patch for critical PTX router RCE](https://securityaffairs.com/188609/security/juniper-issues-emergency-patch-for-critical-ptx-router-rce.html)
    - [Critical Juniper Networks PTX flaw allows full router takeover](https://www.bleepingcomputer.com/news/security/critical-juniper-networks-ptx-flaw-allows-full-router-takeover/)
    - [Juniper PTX Flaw Could Allow Full Router Takeover | eSecurity Planet](https://www.esecurityplanet.com/threats/juniper-ptx-flaw-could-allow-full-router-takeover/)
    - [Juniper Networks PTX Vulnerability Allows Full Router Takeover, Exposing Networks](https://gbhackers.com/juniper-networks-ptx-vulnerability/)
    - [Juniper Networks PTX Routers Affected by Critical Vulnerability - SecurityWeek](https://www.securityweek.com/juniper-networks-ptx-routers-affected-by-critical-vulnerability/)
    - [Juniper Networks PTX Vulnerability Enables Full Router Takeover](https://cybersecuritynews.com/juniper-networks-ptx-vulnerability/)
    - [Juniper PTX Routers at Risk as Critical Vulnerability Enables Full Device Takeover](https://cyberpress.org/juniper-ptx-routers-at-risk/)
    - [NVD - CVE-2026-21902](https://nvd.nist.gov/vuln/detail/CVE-2026-21902)

---

*Last Updated: March 1, 2026* 
