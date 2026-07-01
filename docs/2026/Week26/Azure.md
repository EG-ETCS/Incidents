# Azure CLI Password Spraying Campaign
![alt text](images/Azure.png)

**Password Spraying**{.cve-chip} **Microsoft Entra ID**{.cve-chip} **Azure CLI Abuse**{.cve-chip} **Cloud Account Takeover**{.cve-chip} **BEC Risk**{.cve-chip}

## Overview

Threat actors conducted a large-scale password spraying campaign targeting Microsoft cloud tenants through Azure CLI authentication workflows. Attackers attempted unauthorized access to Microsoft Entra ID (Azure AD) accounts by spraying commonly used and reused passwords across many usernames. The activity used legitimate authentication paths and distributed infrastructure to evade detection, including rotating IP addresses, VPNs, Tor exit nodes, and botnet-origin traffic.

## Technical Specifications

| Attribute | Details |
|---|---|
| **Campaign Type** | Cloud identity password spraying |
| **Target Platform** | Microsoft Entra ID (Azure AD), Microsoft 365 |
| **Abused Interface** | Azure CLI authentication workflows/endpoints |
| **Initial Access Technique** | Credential attack (password spraying) |
| **Evasion Methods** | Rotating IPs, VPN infrastructure, Tor exit nodes, botnet traffic |
| **Observed Signals** | Suspicious Azure CLI user agents, geographically abnormal sign-ins, repeated low-volume failures across many users |
| **Credential Source** | Public profile enumeration, breached datasets, reused password patterns |
| **Persistence Risk** | OAuth token abuse and session persistence post-compromise |
| **CVE IDs** | Not applicable (abuse of legitimate authentication surface) |

## Affected Products

- Microsoft Entra ID tenants with weak password hygiene
- Microsoft 365 accounts without phishing-resistant MFA
- Organizations permitting unrestricted Azure CLI sign-in from unmanaged endpoints
- Tenants lacking Conditional Access and anomaly-based identity detection

## Attack Scenario

1. Threat actors collect employee usernames from public sources (for example, LinkedIn) and prior breach data.
2. Automated tooling submits Azure CLI authentication requests against many accounts.
3. Common or reused passwords are sprayed across multiple users to reduce account lockout likelihood.
4. A successful sign-in provides access to Microsoft cloud services tied to the compromised account.
5. Attackers establish persistence (for example, token/session abuse), steal emails and documents, run internal phishing, and attempt lateral movement or privilege escalation.

## Impact

=== "Integrity"

    - Unauthorized account access can alter mailbox rules, tenant settings, and cloud resource configurations
    - Internal phishing and BEC activity can be launched from trusted compromised accounts
    - Privilege escalation attempts may lead to broader tenant compromise

=== "Confidentiality"

    - Access to Microsoft 365 mailboxes and SharePoint/OneDrive content enables sensitive data theft
    - Exposure of internal communications and identity artifacts increases follow-on attack success
    - OAuth/token abuse can extend attacker visibility without repeated credential use

=== "Availability"

    - Security operations overhead increases due to widespread sign-in attack noise and response workload
    - Account lockouts and remediation efforts can interrupt business operations
    - Compromised privileged identities can impact access continuity across cloud services

## Mitigations

### Immediate Actions

- Enforce phishing-resistant MFA for all users, prioritizing admins and sensitive roles
- Reset credentials for suspected compromised accounts and revoke active sessions/tokens
- Restrict Azure CLI access to approved users, managed devices, and trusted locations

### Short-term Measures

- Implement strong password policy and block password reuse with banned-password controls
- Enable and harden Conditional Access policies (device compliance, location, risk-based controls)
- Block legacy authentication where possible and reduce exposed auth paths

### Monitoring & Detection

- Monitor Microsoft Entra sign-in logs for suspicious Azure CLI user agents and distributed low-and-slow failures
- Detect impossible travel, abnormal geolocation patterns, and unusual sign-in timing
- Correlate SIEM identity alerts with Entra Identity Protection detections for spray patterns

### Long-term Solutions

- Adopt passwordless authentication for high-value roles and broad workforce segments
- Build identity threat hunting playbooks specific to cloud password spraying and token persistence
- Periodically test Conditional Access and incident response controls with red/blue simulations

## Resources

!!! info "Open-Source Reporting"
    - [Azure CLI Password Spray Hits at Least 78 Microsoft Accounts in 81M+ Attempts](https://thehackernews.com/2026/07/azure-cli-password-spray-hits-at-least.html)

---

*Last Updated: July 1, 2026*
