# Cisco Catalyst SD-WAN Manager Authentication Bypass
![alt text](images/Cisco.png)

**Cisco**{.cve-chip} **SD-WAN Manager**{.cve-chip} **CVE-2026-76504**{.cve-chip} **Authentication Bypass**{.cve-chip} **Active Exploitation**{.cve-chip}

## Overview

Cisco disclosed a critical authentication-bypass vulnerability in the API session-authentication mechanism of Cisco Catalyst SD-WAN Manager.

The flaw allows an unauthenticated remote attacker to bypass authentication and obtain API access with administrator privileges. Cisco confirmed active exploitation in September 2026.

## Technical Details

CVE-2026-76504 is caused by improper handling of URI encoding (CWE-177).

Attackers can manipulate encoded characters in HTTP requests to bypass the authentication rule protecting the `j_security_check` endpoint. Cisco identified request patterns such as `/%6a_security_check`, where `%6a` represents `j`.

- No valid credentials are required.
- No user interaction is required.
- Exploitation targets API session-authentication controls.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **CVE** | CVE-2026-76504 |
| **Component** | Cisco Catalyst SD-WAN Manager API session-authentication mechanism |
| **Weakness** | Improper handling of URI encoding (CWE-177) |
| **Exploit Characteristic** | Encoded-path manipulation bypassing `j_security_check` protection |
| **Privilege Obtained** | Administrator-level API access |
| **Exploitation Status** | Cisco-confirmed active exploitation (September 2026) |

## Affected Products

- Cisco Catalyst SD-WAN Manager deployments running vulnerable releases.
- Internet-exposed management interfaces are especially high risk.

## Attack Scenario

1. Attacker identifies an exposed Cisco Catalyst SD-WAN Manager instance.
2. Attacker sends a specially crafted HTTP request containing URI-encoded characters.
3. Authentication controls are bypassed.
4. Attacker obtains administrative API access.
5. Attacker can modify SD-WAN configurations or perform other privileged management operations.

## Impact Assessment

=== "Primary Impact"

    - Unauthorized administrator-level access to SD-WAN Manager API
    - Potential manipulation of SD-WAN policies and centralized network control

=== "Operational Risk"

    - Unauthorized configuration changes may disrupt connectivity and services
    - Sensitive management information may be exposed
    - Centralized compromise can impact multiple connected sites

=== "Severity"

    - **Critical** due to unauthenticated remote exploitability and administrator-level access

## Mitigation Strategies

1. Upgrade to fixed Cisco releases as soon as possible.
2. Fixed releases include:

    - `20.9.10.1`
    - `20.12.8.2`
    - `20.15.6.1`
    - `20.18.4.1`
    - `26.1.2.1`
    - `26.2.1`

3. Restrict Internet exposure of SD-WAN Manager.
4. Permit management access only from trusted networks.
5. Apply firewall controls around management interfaces.
6. Monitor authentication and API logs for anomalous requests.
7. Investigate suspicious URI-encoded requests targeting authentication endpoints.

Cisco states there is no workaround that fixes the vulnerability itself.

## Resources and References

!!! info "Public Reporting"
    - [Cisco Warns of Attackers Exploiting Critical Authentication Bypass in SD-WAN Manager](https://thehackernews.com/2026/09/cisco-warns-of-attackers-exploiting.html)
    - [Cisco Catalyst SD-WAN Manager API Authentication Bypass Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-webauth-xr8beuuU)

---

*Last Updated: October 1, 2026*
