# Philippine Nuclear and Naval Targets Hit by Suspected Chinese Operator
![alt text](images/Philippine.png)

**Cyber Espionage**{.cve-chip} **Critical Infrastructure Targeting**{.cve-chip} **Maritime Defense Sector**{.cve-chip} **CVE-2023-49105**{.cve-chip} **CVE-2024-28000**{.cve-chip}

## Overview

A suspected Chinese-speaking threat operator compromised a Philippine nuclear research organization and a marine engineering and shipbuilding company supporting the Philippine Navy. Researchers reported exploitation of known vulnerabilities in internet-facing ownCloud and WordPress systems, followed by theft of sensitive data.

The operation targeted organizations tied to national critical infrastructure and defense-adjacent maritime capabilities, increasing long-term espionage and operational risk.

## Technical Details

The nuclear-sector target was reportedly compromised via **CVE-2023-49105**, an authentication-bypass issue affecting vulnerable ownCloud WebDAV functionality. Attackers used custom Python tooling to generate accepted WebDAV requests, then enumerate and download files.

The naval-linked target was reportedly compromised via **CVE-2024-28000** in the LiteSpeed Cache WordPress plugin, enabling unauthorized administrator access. The operator also used XML-RPC password attacks against administrative accounts.

An exposed attacker server reportedly contained Python scripts, transfer logs, stolen data, and offensive tooling including **Sliver**, **Metasploit**, and **Mettle**.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Suspected Threat Operator** | Chinese-speaking actor (reported) |
| **Primary Target 1** | Philippine nuclear research organization |
| **Primary Target 2** | Marine engineering/shipbuilding company supporting the Philippine Navy |
| **Initial Access Vector 1** | Exploitation of ownCloud WebDAV via CVE-2023-49105 |
| **Initial Access Vector 2** | Exploitation of LiteSpeed Cache plugin via CVE-2024-28000 |
| **Additional Access Method** | XML-RPC password attacks on WordPress admin |
| **Observed Tooling** | Custom Python scripts, Sliver, Metasploit, Mettle |
| **Recovered Exfil Indicator** | CSV reference of approximately 9 GB stolen data |

## Affected Products

- ownCloud instances vulnerable to CVE-2023-49105 (reported as exploited).
- WordPress deployments using vulnerable LiteSpeed Cache plugin versions prior to 6.4.
- WordPress environments exposing XML-RPC and weak administrator credential hygiene.

## Attack Scenario

1. Reconnaissance identifies internet-facing ownCloud and WordPress targets.
2. Initial access is gained by exploiting CVE-2023-49105 and CVE-2024-28000, plus XML-RPC password attacks.
3. Adversary accesses files and administrative functions in compromised platforms.
4. Discovery and collection focuses on technical, personnel, financial, and strategic documents.
5. Data is exfiltrated using custom scripts with randomized delays to reduce detection likelihood.
6. Stolen credentials and organizational data are positioned for follow-on espionage or intrusion activity.

## Impact Assessment

=== "Reported Compromise Scope"

    - Nuclear research and naval-linked maritime organizations in the Philippines were reportedly compromised
    - Sensitive operational, technical, and personnel data was reportedly accessed and stolen
    - Exposed attacker infrastructure reportedly included transfer logs and stolen-data artifacts

=== "Reported Data Exposure"

    - Nuclear reactor component databases and fuel inventory information
    - Radiation safety documents, incident records, and authorized-user lists
    - IT documentation, employee records, CVs, passport/travel data, and financial disclosures
    - Recovered CSV data referenced approximately 9 GB of stolen material, with potential for larger total theft

=== "Potential Follow-on Risk"

    - Credential-enabled persistence and additional account compromise
    - Spear-phishing and social engineering against identified staff
    - Long-term espionage opportunities against critical infrastructure and defense-support entities

## Mitigation Strategies

### ownCloud Hardening

- Upgrade ownCloud to a patched version (Security Affairs cites 10.13.3 or later).
- Apply vendor fixes and verify strong, non-empty pre-signed URL signing keys.
- Monitor WebDAV usage for suspicious PROPFIND patterns and atypical bulk file downloads.

### WordPress Security Controls

- Update LiteSpeed Cache to version 6.4 or later.
- Audit and remove unauthorized administrator accounts.
- Enforce strong unique passwords and MFA for privileged users.
- Restrict or disable XML-RPC where not operationally required.

### General Defensive Actions

- Maintain continuous vulnerability management and rapid patching of internet-facing services.
- Strengthen log monitoring, anomaly detection, and alert triage for credential abuse and exfiltration activity.
- Segment sensitive environments and review exposure of credential stores and critical data repositories.
- Investigate potential credential compromise and force credential resets where exposure is suspected.

## Resources and References

!!! info "Public Reporting"
    - [Philippine Nuclear and Naval Targets Hit by Suspected Chinese Operator](https://securityaffairs.com/198041/intelligence/philippine-nuclear-and-naval-targets-hit-by-suspected-chinese-operator.html)

---

*Last Updated: August 31, 2026*