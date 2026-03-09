# CVE-2026-3804 – Tenda i3 Router Stack-Based Buffer Overflow
![alt text](images/tenda.png)

**CVE-2026-3804**{.cve-chip}  **Stack Overflow**{.cve-chip}  **CWE-121**{.cve-chip}  **Router RCE Risk**{.cve-chip}

## Overview
CVE-2026-3804 is a vulnerability in Tenda i3 router firmware version `1.0.0.6(2204)` caused by improper input validation in the web management interface. Attackers can manipulate specific request parameters to trigger a stack-based buffer overflow, potentially leading to unauthorized control of the device.

If exploited, the flaw can allow memory corruption, service instability, and potential arbitrary code execution in router context.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **CVE ID** | CVE-2026-3804 |
| **Vulnerability Type** | Stack-based buffer overflow (CWE-121) |
| **CVSS Score** | 7.4 (High) |
| **Affected Product** | Tenda i3 Wi-Fi router |
| **Affected Firmware** | 1.0.0.6(2204) |
| **Vulnerable Endpoint** | `/goform/WifiMacFilterSet` |
| **Vulnerable Function** | `formWifiMacFilterSet` |
| **Vulnerable Parameter** | `index` |
| **Exploit Outcome** | Potential arbitrary code execution, unauthorized control, or DoS |

## Affected Products
- Tenda i3 routers running firmware `1.0.0.6(2204)`
- Devices exposing web management interface to local or internet-reachable networks
- Environments with remote administration enabled without strict access controls
- Legacy/unpatched home or SMB edge deployments
- Status: High risk until updated or isolated

## Technical Details

### Root Cause
- Input passed via the `index` parameter is not adequately validated.
- Crafted payloads can exceed expected buffer boundaries in `formWifiMacFilterSet`.
- Memory corruption occurs on the stack, enabling crash or controlled overwrite conditions.

### Vulnerable Path
- HTTP request targeting `/goform/WifiMacFilterSet`
- Maliciously manipulated `index` value triggers overflow in firmware handler

### Security Consequence
- Stack corruption can lead to process crash (availability impact).
- Under favorable conditions, attacker may gain code execution/control in device context.

## Attack Scenario
1. **Target Discovery**:
    - Attacker identifies reachable Tenda i3 routers (internet-exposed or local network).

2. **Crafted Request Delivery**:
    - Attacker sends malicious HTTP request to `/goform/WifiMacFilterSet`.

3. **Parameter Manipulation**:
    - `index` parameter is populated with overflow-triggering payload.

4. **Overflow Trigger**:
    - Firmware function fails to validate bounds and overwrites stack memory.

5. **Post-Exploitation Outcome**:
    - Device may crash (DoS) or attacker may gain unauthorized control for persistence/traffic abuse.

## Impact Assessment

=== "Integrity"
    * Unauthorized administrative control of router settings
    * Malicious configuration changes (DNS/routing/firewall)
    * Potential implantation of persistent malicious logic

=== "Confidentiality"
    * Interception or redirection of user traffic
    * Increased risk of credential/session capture via MITM behavior
    * Exposure of internal network patterns via compromised gateway

=== "Availability"
    * Service crash or repeated instability from overflow exploitation
    * Potential participation in botnet activity affecting network performance
    * Loss of connectivity and operational disruption for dependent users

## Mitigation Strategies

### Immediate Actions
- Update firmware to latest vendor release as patches become available
- Disable remote administration where not required
- Restrict management access to trusted internal networks only

### Detection and Monitoring
- Monitor logs for suspicious requests targeting `/goform/*` endpoints
- Alert on repeated malformed management requests and unexplained config changes
- Track unexpected reboot/crash patterns indicating exploitation attempts

### Long-Term Risk Reduction
- Replace unsupported or unpatched routers with maintained models
- Segment edge management interfaces from untrusted network zones
- Periodically audit internet exposure of router administration services

## Resources and References

!!! info "Open-Source References"
    - [NVD - CVE-2026-3804](https://nvd.nist.gov/vuln/detail/CVE-2026-3804)
    - [CVE-2026-3804 - Tenda i3 WifiMacFilterSet formWifiMacFilterSet stack-based overflow](https://cvefeed.io/vuln/detail/CVE-2026-3804)
    - [CVE-2026-3803 : A vulnerability was identified in Tenda i3 1.0.0.6(2204)](https://www.cvedetails.com/cve/CVE-2026-3803/)

---

*Last Updated: March 9, 2026* 
