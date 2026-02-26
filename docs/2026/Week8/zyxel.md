# Zyxel Warns of Critical RCE Flaw Affecting Over a Dozen Routers
![alt text](images/zyxel.png)

**CVE-2025-13942**{.cve-chip}  **Remote Code Execution**{.cve-chip}  **UPnP SOAP Injection**{.cve-chip}  **CVSS 9.8**{.cve-chip}

## Overview
Zyxel patched a critical remote code execution vulnerability in the UPnP feature of more than a dozen router/CPE models, including 4G/5G CPE, DSL/Ethernet CPE, fiber ONTs, and Wi-Fi extenders. Tracked as CVE-2025-13942 (CVSS 9.8), the flaw allows unauthenticated attackers to execute OS commands via crafted UPnP SOAP requests when devices are exposed and UPnP is enabled.

In the same release, Zyxel also fixed two high-severity post-authentication command-injection vulnerabilities (CVE-2025-13943 and CVE-2026-1459) in log-download and TR-369 certificate functions, which can be abused with valid admin credentials to execute OS commands.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Primary CVE** | CVE-2025-13942 |
| **Vulnerability Type** | Command injection in UPnP SOAP handling |
| **Severity** | CVSS 9.8 (Critical) |
| **Attack Preconditions** | WAN access + UPnP enabled (non-default remote exposure condition) |
| **Authentication Requirement** | None (for CVE-2025-13942) |
| **Additional CVEs** | CVE-2025-13943, CVE-2026-1459 (post-auth command injection) |
| **Affected Product Families** | 4G/5G CPE, DSL/Ethernet CPE, fiber ONTs, wireless extenders |
| **Exploitation Scope** | Internet-exposed/misconfigured devices at elevated risk |

## Affected Products
- Multiple Zyxel router and CPE product lines (more than a dozen models per advisory)
- 4G LTE / 5G NR CPE devices
- DSL and Ethernet CPE devices
- Fiber ONTs and wireless range extenders
- Status: Patched by Zyxel; exposed unpatched devices remain high risk

![alt text](images/zyxel1.png)

## Technical Details

### Primary Pre-Auth RCE (CVE-2025-13942)
- Command injection exists in the UPnP function.
- An unauthenticated remote attacker can send crafted UPnP SOAP requests to execute OS commands.
- Remote exploitability depends on configuration: WAN access is disabled by default and attack requires both WAN access and UPnP to be enabled.

### Additional Post-Auth Command Injection
- CVE-2025-13943 and CVE-2026-1459 affect log-download and TR-369 certificate functions.
- These paths require valid administrative credentials.
- Successful abuse can still result in OS command execution and full device compromise.

### Exposure Context
- Zyxel indicates broad model impact across product categories.
- External telemetry has identified a large population of internet-exposed Zyxel systems, with a subset potentially vulnerable due to risky WAN/UPnP configurations.

## Attack Scenario
1. **Internet Reconnaissance**:
    - Attacker scans for Zyxel devices with externally reachable services and UPnP exposure.

2. **Pre-Auth Exploitation Path**:
    - Where WAN access and UPnP are enabled, attacker sends crafted SOAP payloads.
    - Input reaches vulnerable command-execution path and runs OS commands on device.

3. **Device Takeover Actions**:
    - Attacker modifies firewall/NAT policies, deploys malware, and establishes remote shell/persistence.

4. **Post-Auth Alternate Path**:
    - If admin credentials are available, attacker abuses CVE-2025-13943 / CVE-2026-1459 via log-download or TR-369 certificate functions to execute OS commands.

5. **Follow-on Abuse**:
    - Compromised routers/CPEs are used for DNS hijacking, traffic interception, lateral movement, botnet enrollment, or DDoS operations.

## Impact Assessment

=== "For Users and SMBs"
    * Full router control and persistent compromise of edge network equipment
    * DNS/routing manipulation leading to phishing, interception, or redirection
    * Increased risk of malware deployment and botnet enrollment

=== "For ISPs and Enterprises"
    * Fleet-level compromise risk across customer-premises infrastructure
    * Potential man-in-the-middle operations and distributed DDoS abuse
    * Router footholds can act as beachheads into corporate/home networks

=== "Business and Security Risk"
    * Critical edge-device exposure due to unauthenticated remote exploit path
    * Threat to confidentiality, integrity, and availability of connected environments
    * High operational urgency where WAN+UPnP misconfiguration exists

## Mitigation Strategies

### Patch Immediately
- Install the latest Zyxel firmware for all affected models per Zyxel advisory
- Prioritize high-risk internet-exposed devices first

### Reduce Exposure
- Disable WAN management and UPnP unless strictly required
- Avoid exposing management interfaces directly to the internet
- Restrict remote administration via VPN or trusted management networks only

### Harden Authentication
- Use strong, unique admin credentials across all devices
- Rotate credentials where compromise is suspected
- Enable additional authentication controls where supported

### Monitor and Inventory
- Inventory exposed Zyxel devices and validate WAN/UPnP reachability from external networks
- Monitor for unusual outbound traffic, unauthorized config changes, suspicious processes, new admin accounts, and altered DNS settings
- Hunt for signs of compromise in router/CPE logs and management events

## Resources and References

!!! info "Vendor and Security Reporting"
    - [Security Advisories | Zyxel Networks](https://www.zyxel.com/global/en/support/security-advisories)
    - [Zyxel warns of critical RCE flaw affecting over a dozen routers](https://www.bleepingcomputer.com/news/security/zyxel-warns-of-critical-rce-flaw-affecting-over-a-dozen-routers/)
    - [Critical Zyxel router flaw exposed devices to remote attacks](https://securityaffairs.com/188501/security/critical-zyxel-router-flaw-exposed-devices-to-remote-attacks.html)
    - [NVD-CVE-2025-13942](https://nvd.nist.gov/vuln/detail/CVE-2025-13942)

---

*Last Updated: February 26, 2026* 
