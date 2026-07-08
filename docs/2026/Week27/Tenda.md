# Hidden Backdoor in Tenda Router Firmware (CVE-2026-11405)
![alt text](images/Tenda.png)

**CVE-2026-11405**{.cve-chip} **Authentication Bypass**{.cve-chip} **Hardcoded Secret**{.cve-chip} **Router Backdoor**{.cve-chip} **No Patch at Disclosure**{.cve-chip}

## Overview

Researchers identified a hidden authentication backdoor in multiple Tenda router firmware versions. The undocumented mechanism allows anyone with a hardcoded secret password to bypass normal administrator authentication and gain full administrative access to the web management interface. The issue is tracked as CVE-2026-11405. At disclosure time, no official vendor patch was available due to unsuccessful coordinated disclosure.

## Technical Specifications

| Attribute | Details |
|---|---|
| **CVE ID** | CVE-2026-11405 |
| **Vulnerability Type** | Hidden authentication backdoor / authentication bypass |
| **Affected Component** | Embedded HTTP server (`/bin/httpd`) in Tenda firmware |
| **Root Cause** | Undocumented auth routine accepts hardcoded secret password independent of configured admin credentials |
| **Authentication Required** | Knowledge of hardcoded secret only |
| **Access Vector** | Web management interface (local or remote if exposed) |
| **Known Affected Product Lines** | FH1201, W15E, AC10, AC5, AC6 series |
| **Patch Status at Disclosure** | No official firmware patch available |
| **Disclosure Source** | CERT/CC VU#213560 |

## Affected Products

- Tenda routers running vulnerable firmware with hidden backdoor logic
- Products reported as affected include FH1201, W15E, AC10, AC5, and AC6 series
- Deployments with remote management enabled or internet-exposed management interfaces are at highest risk

## Attack Scenario

1. Attacker identifies a vulnerable Tenda router model/firmware.
2. Attacker reaches the router management interface locally or remotely (if exposed).
3. Attacker submits the hidden hardcoded secret password.
4. Firmware creates an administrator session without validating the configured admin password.
5. Attacker gains full administrative control and can alter settings, create persistence, hijack DNS, weaken firewall/NAT, monitor traffic, and pivot into internal systems.

## Impact

=== "Integrity"

    - Full unauthorized administrative control of the router configuration
    - Security control tampering, including firewall/NAT policy manipulation
    - Persistent unauthorized access through admin/session persistence changes

=== "Confidentiality"

    - DNS hijacking can redirect users to phishing and credential theft pages
    - Traffic interception and monitoring risks exposure of sensitive data
    - Router compromise can expose internal network topology for lateral movement

=== "Availability"

    - Service disruption via malicious configuration changes or traffic rerouting
    - Router destabilization or abuse in botnet operations and downstream attacks
    - Increased operational risk for homes/SMBs relying on affected edge devices

## Mitigations

### Immediate Actions

- Disable remote management unless strictly required
- Restrict router administrative access to trusted internal addresses only
- Block internet access to management interfaces using upstream/firewall ACLs

### Short-term Measures

- Place management interfaces on a dedicated management VLAN where possible
- Audit admin accounts and monitor for unauthorized configuration changes
- Regularly verify DNS settings and restore known-good resolver configuration if altered

### Monitoring & Detection

- Alert on unexpected login/session creation events to router admin interfaces
- Monitor configuration drift, especially firewall/NAT and DNS parameters
- Track CERT/CC and Tenda advisories for IOC and remediation updates

### Long-term Solutions

- Replace affected devices if secure isolation cannot be guaranteed
- Apply official firmware updates immediately when released
- Adopt lifecycle management to retire unsupported/EoL network edge equipment proactively

## Resources

!!! info "Open-Source Reporting"
    - [VU#213560 - Tenda firmware (multiple versions) contains hidden authentication backdoor](https://kb.cert.org/vuls/id/213560)
    - [Hidden Tenda Router Backdoor Grants Admin Access, No Patch Available](https://securityaffairs.com/194878/security/hidden-tenda-router-backdoor-grants-admin-access-no-patch-available.html)
    - [Hidden backdoor in Tenda router firmware grants admin access](https://www.bleepingcomputer.com/news/security/hidden-backdoor-in-tenda-router-firmware-grants-admin-access/)
    - [CERT/CC Warns of Hidden Admin Backdoor in Tenda Router Firmware](https://thehackernews.com/2026/07/certcc-warns-of-hidden-admin-backdoor.html)

---

*Last Updated: July 8, 2026*
