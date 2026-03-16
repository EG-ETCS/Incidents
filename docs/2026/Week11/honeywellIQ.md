# Honeywell IQ4x BMS Authentication Bypass Vulnerability
![alt text](images/honeywellIQ.jpg)

**BMS Security**{.cve-chip} **Authentication Bypass**{.cve-chip} **Critical Infrastructure**{.cve-chip}

## Overview

A critical vulnerability was identified in Honeywell IQ4x Building Management System (BMS) controllers. The issue can allow unauthenticated attackers to reach the web management interface when devices are deployed with default configurations.

Because authentication is not enabled until initial account setup, an attacker may create administrator credentials and obtain full control of the controller.

## Technical Specifications

| Field | Details |
|-------|---------|
| **Identifier** | CVE-2026-3611 |
| **CVSS Score** | 10 (Critical) |
| **Affected Product** | Honeywell IQ4x BMS controllers |
| **Vulnerability Type** | Authentication bypass / improper access control during initial setup |
| **Exposed Component** | Web-based HMI over HTTP |
| **Authentication State** | Disabled by default until first account creation |
| **Potential Outcome** | Unauthorized admin account creation and full controller takeover |

## Affected Products

- Honeywell IQ4x BMS controllers using default or incomplete initial configuration.
- Deployments where management interfaces are exposed to internal broad networks or the public internet.

## Technical Details

- The issue stems from missing authentication checks during initial HMI setup.
- A user creation endpoint can be reached before authentication is configured.
- The system starts in a "System Guest" state with read/write permissions.
- Attackers can create a new administrative user and enable authentication with attacker-controlled credentials.
- This sequence results in complete administrative access to the BMS controller.

## Attack Scenario

1. An attacker scans internet-facing or internal network ranges for exposed Honeywell IQ4x devices.
2. The attacker opens the vulnerable device web interface.
3. With authentication not yet enabled, the attacker accesses the user creation function.
4. A new administrator account is created by the attacker.
5. The attacker signs in with the newly created credentials and gains full control of the controller.

## Impact Assessment

=== "Operational Impact"
    Attackers can take control of building automation workflows and disrupt facility operations.

=== "Control and Safety Impact"
    Adversaries may alter HVAC, lighting, and energy management settings, with potential downstream effects on safety-sensitive environments.

=== "Administrative Impact"
    Legitimate administrators may be locked out while unauthorized changes are made to controller configuration.

## Mitigation Strategies

- Upgrade controller firmware to version 4.36 or later.
- Create administrator accounts immediately after deployment.
- Ensure authentication is enabled before exposing devices to any untrusted network.
- Restrict access using firewalls, ACLs, and network segmentation.
- Avoid direct public internet exposure of controller management interfaces.
- Monitor logs for unauthorized account creation and suspicious configuration changes.

## Resources

!!! info "Open-Source Reporting"
    - [NVD - CVE-2026-3611](https://nvd.nist.gov/vuln/detail/CVE-2026-3611)
    - [Honeywell IQ4x BMS Controller | CISA](https://www.cisa.gov/news-events/ics-advisories/icsa-26-069-03)
    - [Critical Authentication Bypass in Honeywell IQ4x BMS Controllers (CVE-2026-3611) Threatens Facility Operations - LiveThreat](https://www.livethreat.ai/intelligence/honeywell-iq4x-bms-controller-3156)
    - [Honeywell IQ4x BMS Controller - Security / Security Bulletins - I.T. Bible - Community](https://community.itbible.org/t/honeywell-iq4x-bms-controller/2685)
    - [CVE-2026-3611 - Unauthenticated Web Interface Takeover in... ](https://vulmon.com/vulnerabilitydetails?qid=CVE-2026-3611)
    - [CVE-2026-3611 - Honeywell IQ4x - Broken Access Control | LeakyCreds](https://www.leakycreds.com/vulnerability/CVE-2026-3611)

---
*Last Updated: March 16, 2026*