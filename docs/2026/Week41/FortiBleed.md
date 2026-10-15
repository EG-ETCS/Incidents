# FortiBleed Campaign
![alt text](images/FortiBleed.png)

**FortiBleed**{.cve-chip} **Fortinet FortiGate**{.cve-chip} **SSL VPN**{.cve-chip} **Credential Attacks**{.cve-chip} **Firewall Intrusion**{.cve-chip}

## Overview

A cybercrime campaign is targeting internet-facing Fortinet FortiGate firewalls and SSL VPN services.

Attackers are reported to exploit stolen, leaked, or reused credentials to gain unauthorized access. Compromised devices may then be used for persistent access, administrator-account manipulation, and further network intrusion.

## Technical Details

Observed and reported campaign methods include:

- Scanning exposed firewall and VPN interfaces.
- Credential stuffing and password spraying.
- Offline cracking of legacy password hashes.
- Unauthorized administrator account creation and modification.
- Potential lateral movement into internal networks.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Campaign Name** | FortiBleed |
| **Primary Targets** | Internet-facing Fortinet FortiGate firewalls and SSL VPN portals |
| **Initial Access Vector** | Stolen, leaked, or reused credentials |
| **Technique Pattern** | Interface scanning, credential attacks, hash cracking, admin-account abuse |
| **Post-Access Risk** | Persistent foothold and possible lateral movement into internal network zones |
| **Incident Theme** | Identity compromise and perimeter control-plane takeover |

## Affected Products

- Fortinet FortiGate firewall management interfaces exposed to the internet.
- Fortinet SSL VPN services with weak, reused, or previously compromised credentials.
- Environments using legacy password-hash schemes not yet migrated per vendor guidance.

## Attack Scenario

1. Identify exposed FortiGate devices and VPN entry points.
2. Obtain, reuse, or crack administrator credentials.
3. Authenticate to vulnerable or poorly secured management interfaces.
4. Create unauthorized administrator accounts or modify existing ones.
5. Explore internal systems and potentially facilitate ransomware operations.

## Impact Assessment

=== "Security and Access Impact"

    - Unauthorized firewall administration
    - Loss of legitimate administrator access
    - Credential and sensitive information exposure

=== "Infrastructure Impact"

    - Unauthorized network configuration changes
    - Expanded attacker persistence on perimeter infrastructure

=== "Business Risk"

    - Increased likelihood of data breaches, lateral movement, and ransomware events

## Mitigation Strategies

1. Restrict public access to firewall management interfaces.
2. Reset compromised and reused passwords.
3. Enforce multifactor authentication (MFA).
4. Audit administrator accounts and authentication logs.
5. Upgrade FortiOS and follow Fortinet password-hash migration guidance.
6. Investigate internal networks for suspicious activity.
7. Maintain secure configuration backups and incident recovery procedures.

## Resources and References

!!! info "Public Reporting"
    1. [FortiBleed hit 86,000 firewalls by exploiting something nobody can patch away](https://securityaffairs.com/200558/cyber-crime/fortibleed-hit-86000-firewalls-by-exploiting-something-nobody-can-patch-away.html)
    2. [FBI warns that FortiBleed credential-harvesting attacks are locking out firewall users | Cybersecurity Dive](https://www.cybersecuritydive.com/news/fbi-fortibleed-credential-harvesting-attacks/832366/)

---

*Last Updated: October 15, 2026*
