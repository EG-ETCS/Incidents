# Veeam Backup & Replication Remote Code Execution Vulnerability
![alt text](images/Veeam.png)

**CVE-2026-44963**{.cve-chip} **Remote Code Execution**{.cve-chip} **Backup Infrastructure**{.cve-chip} **Ransomware Risk**{.cve-chip}

## Overview

A critical vulnerability in Veeam Backup & Replication allows authenticated low-privileged domain users to execute arbitrary code remotely on vulnerable backup servers. Since backup infrastructure is highly sensitive and often connected to core enterprise systems, successful exploitation may lead to full infrastructure compromise and ransomware deployment. The flaw affects domain-joined servers running version 12.3.2.4465 and earlier, and has been patched in version 12.3.2.4854.

## Technical Specifications

| Attribute | Details |
|---|---|
| **CVE ID** | CVE-2026-44963 |
| **Vulnerability Type** | Remote Code Execution |
| **CVSS Score** | Critical |
| **Attack Vector** | Network |
| **Authentication** | Low-privileged domain user (Active Directory account required) |
| **Complexity** | Low |
| **User Interaction** | Not Required |
| **Affected Versions** | Veeam Backup & Replication 12.3.2.4465 and earlier (domain-joined) |
| **Fixed Version** | 12.3.2.4854 |
| **Unaffected** | Veeam Backup & Replication 13.x (architectural changes) |

## Affected Products

- Veeam Backup & Replication 12.3.2.4465 and earlier
- Domain-joined Veeam backup servers with Active Directory integration
- Enterprise environments where backup servers are accessible to domain users

## Attack Scenario

1. Attacker compromises a low-privileged employee domain account via phishing, credential theft, or another intrusion method.
2. Using the compromised AD account, the attacker targets the vulnerable Veeam backup server.
3. Attacker exploits CVE-2026-44963 to achieve remote code execution on the backup server.
4. Attacker moves laterally within the environment using backup server access.
5. Attacker disables or deletes backups to prevent recovery, steals credentials, and deploys ransomware across the environment.

## Impact

=== "Integrity"

    - Full compromise of backup infrastructure with remote code execution capabilities
    - Deletion or encryption of backups, eliminating disaster recovery options
    - Ransomware deployment across the enterprise environment

=== "Confidentiality"

    - Credential theft from the backup server and connected systems
    - Access to sensitive backup data including databases, files, and system images
    - Exposure of Tier-0 asset configurations and enterprise infrastructure details

=== "Availability"

    - Operational disruption and data loss from backup destruction
    - Inability to recover critical systems following a ransomware attack
    - Extended downtime due to loss of backup and recovery capabilities

## Mitigations

### Immediate Actions

- Upgrade immediately to Veeam Backup & Replication **12.3.2.4854** or later
- Restrict domain user access to backup servers and review service account permissions
- Segment backup servers from production networks

### Short-term Measures

- Enable MFA for all administrative and backup infrastructure accounts
- Use immutable and offline backups to protect against deletion or encryption
- Limit Active Directory accounts with access to backup infrastructure

### Monitoring & Detection

- Monitor for suspicious authentication attempts targeting backup servers
- Alert on anomalous PowerShell activity, backup deletion events, and lateral movement
- Deploy EDR monitoring on backup infrastructure

### Long-term Solutions

- Treat backup servers as Tier-0 assets with hardened access controls
- Enforce network segmentation and zero-trust policies around backup infrastructure
- Maintain offline, air-gapped backup copies to ensure recoverability

## Resources

!!! info "Open-Source Reporting"
    - [Critical Veeam RCE flaw Lets Low-Privilege Users Take Over Backup Servers](https://securityaffairs.com/193385/uncategorized/critical-veeam-rce-flaw-lets-low-privilege-users-take-over-backup-servers.html)
    - [Critical RCE in Veeam Backup & Replication Exposes Domain-Joined Servers | Mallory](https://www.mallory.ai/stories/019eacec-659d-7808-bda2-7a654bb3b875)
    - [CVE-2026-44963 | Tenable®](https://www.tenable.com/cve/CVE-2026-44963)

---

*Last Updated: June 10, 2026*
