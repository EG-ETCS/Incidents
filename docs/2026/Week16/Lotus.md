# New Lotus Data Wiper Used Against Venezuelan Energy and Utility Firms
![alt text](images/Lotus.png)

**Data Wiper**{.cve-chip} **Critical Infrastructure**{.cve-chip} **Destructive Malware**{.cve-chip} **Energy Sector**{.cve-chip}

## Overview

Lotus Wiper is a previously undocumented destructive malware deployed against energy and utilities organizations in Venezuela in late 2025. Unlike ransomware, it has no extortion mechanism — its sole purpose is irreversible data and system destruction, rendering Windows hosts unbootable and unrecoverable. Researchers link the campaign to the period of political instability surrounding Venezuela's Maduro government, and note alignment with a concurrent attack on state-owned oil company PDVSA, suggesting a strategic, state-aligned sabotage operation rather than financially motivated crime.

## Technical Specifications

| Attribute | Details |
|---|---|
| **Malware Type** | Data wiper (destructive, not ransomware) |
| **Target OS** | Windows (domain-joined systems) |
| **Targeted Sector** | Energy and utilities organizations — Venezuela |
| **Attack Chain** | Batch scripts (OhSyncNow.bat, notesreg.bat) + compiled Lotus Wiper binary |
| **Deployment Mechanism** | NETLOGON share / domain-wide distribution |
| **Key Techniques** | diskpart clean all, robocopy overwrite, fsutil fill, IOCTL disk wipe, USN journal clearing |
| **Recovery Prevention** | Deletes all Windows restore points; overwrites physical sectors |
| **CVE** | None — assumes prior compromise with high privileges |
| **Motivation** | Destructive / strategic sabotage — no C2, no ransom note |

## Affected Products

- **Windows domain-joined systems** in energy and utilities environments
- **Physical disks** — all sectors overwritten via IOCTL operations
- **OT-adjacent IT networks** — systems supporting energy dispatch, monitoring, and logistics

## Attack Scenario

1. Attacker gains persistent, high-privilege access to the target's domain environment (vector undisclosed — likely phishing, exposed services, or supply chain)
2. Batch scripts (`OhSyncNow.bat`, `notesreg.bat`) and the Lotus binary are distributed to domain-joined hosts via NETLOGON share or GPO
3. Scripts coordinate near-simultaneous execution: disable `UI0Detect`, disable network interfaces, disable accounts, and log off active sessions — isolating hosts and blocking remote response
4. Native Windows tools are used destructively: `diskpart clean all` overwrites drives, `robocopy` overwrites directory contents, `fsutil` fills remaining free space
5. Scripts decrypt and execute the Lotus Wiper binary, which performs low-level physical disk wiping via Windows IOCTLs, deletes restore points, clears the USN journal, and zeros all file contents
6. Systems become unbootable and unrecoverable; full environment rebuilds are required

## Impact

=== "Technical Impact"

    - Complete, irreversible destruction of data across all targeted domain-joined hosts
    - Physical sector overwriting prevents recovery even with forensic tools
    - USN journal clearing removes file-system activity traces, complicating forensics
    - Mass account disabling and network interface teardown block real-time defender response
    - No built-in rollback — restore points deleted before final wipe

=== "Operational Impact"

    - Simultaneous crippling of large portions of an energy/utility network
    - Disruption of IT systems supporting billing, scheduling, dispatch, and monitoring
    - Concurrent PDVSA attack suggests coordinated disruption of Venezuelan fuel and logistics infrastructure

=== "Geopolitical Impact"

    - Campaign aligns with Venezuela's political crisis in late 2025 — assessed as state-aligned strategic sabotage
    - Consistent with historical destructive wiper campaigns against critical infrastructure (Shamoon, NotPetya)
    - Non-monetized, purely destructive design signals political intent over financial motivation

## Mitigations

### Detection — Pre-Destruction Indicators

- Alert on `UI0Detect` service changes, unusual NETLOGON share modifications, and suspicious XML coordination files
- Monitor for mass account password changes, bulk user disabling, and simultaneous network interface disabling
- Alert on unexpected mass use of `diskpart clean all`, `robocopy` against critical paths, or `fsutil` creating large fill files

### Access and Privilege Controls

- Enforce least privilege and regular rotation of domain admin and service account credentials
- Use dedicated admin workstations with MFA and network segmentation to limit high-privilege token abuse

### Network and Script Restriction

- Segment ICS/OT and critical operations from general IT; restrict NETLOGON share reach on sensitive systems
- Implement AppLocker, WDAC, or EDR rules to block unsigned batch scripts and disk tools on critical servers

### Backup and Recovery Resilience

- Maintain **offline or immutable backups** of all critical systems; test restoration from complete disk loss scenarios
- Assume multi-host simultaneous failure in recovery exercises

## Resources

!!! info "Open-Source Reporting"
    - [New Lotus data wiper used against Venezuelan energy, utility firms — BleepingComputer](https://www.bleepingcomputer.com/news/security/new-lotus-data-wiper-used-against-venezuelan-energy-utility-firms/)
    - [Lotus Wiper — Securelist / Kaspersky](https://securelist.com/tr/lotus-wiper/119472/)
    - [New Lotus Malware Targets Venezuelan Energy Firms — TechTextNews](https://techtextnews.com/new-lotus-malware-targets-venezuelan-energy-firms-mo8zh9gdageu)
    - [New Lotus Wiper targets Venezuelan Energy and Utilities — MalwareTips](https://malwaretips.com/threads/new-lotus-wiper-targets-venezuelan-%F0%9F%87%BB%F0%9F%87%AA-energy-and-utilities-with-multi-stage-deployment.141012/)
    - [Lotus Data Wiper — Venezuela Energy Sector Cyberattack — ClearPhish](https://www.clearphish.ai/news/lotus-data-wiper-venezuela-energy-sector-cyberattack)

---

*Last Updated: April 22, 2026*