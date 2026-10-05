# Warlock Ransomware Exploiting Unpatched SharePoint ToolShell Vulnerabilities
![alt text](images/Warlock.png)

**Warlock**{.cve-chip} **Longlegs**{.cve-chip} **Storm-2603**{.cve-chip} **SharePoint ToolShell**{.cve-chip} **BYOVD**{.cve-chip}

## Overview

The Warlock ransomware operation, tracked by Symantec as Longlegs and also known as Storm-2603, continues exploiting year-old Microsoft SharePoint ToolShell vulnerabilities.

Recent reporting describes intrusions affecting at least four organizations including a water utility, telecommunications provider, regional government body, and university across Portuguese- and Spanish-speaking countries in Europe, Africa, and Latin America.

This is an ongoing campaign rather than a single event. Attackers use unpatched on-premises SharePoint for initial access, deploy web shells, escalate execution, move laterally, disable endpoint defenses, and deploy ransomware at scale.

## Technical Details

### Threat Actor and Campaign Context

- Ransomware family: Warlock.
- Threat actor tracking: Longlegs (Symantec), also known as Storm-2603.
- Related tracking clusters cited in reporting: CL-CRI-1040, CamoFei, and ChamelGang.
- These labels are vendor tracking context and are not a new public government attribution.

### Initial Access and SharePoint Execution Chain

- Entry vector: unpatched on-premises Microsoft SharePoint ToolShell-related weaknesses.
- Web shell deployment in the SharePoint LAYOUTS directory to maintain access across versions.
- Theft of ASP.NET machine keys from SharePoint server configuration.
- Forged signed payload creation and deserialization gadget abuse to execute code inside SharePoint.

### Post-Exploitation Tradecraft

- DLL sideloading used for follow-on payload execution.
- Payload retrieval from legitimate hosting services (including catbox.moe and wasabisys.com).
- Burp Collaborator subdomain including target-domain indicators used to validate code execution.
- Visual Studio Code tunneling abused for covert remote access that can blend into normal developer traffic.

### Defense Evasion and Domain-Scale Deployment

- Signed but vulnerable K7RKScan driver used for BYOVD-based AV/EDR disablement.
- Security-disable tooling reportedly pushed to at least 40 hosts within roughly two hours in one critical-infrastructure intrusion.
- Domain account `SPSEPRDSetup` added to local Administrators groups on multiple hosts.
- Ransomware staged in SYSVOL to leverage normal Active Directory replication.
- `dfsrs.exe` observed distributing malicious files via standard DFS replication channels.
- Warlock payload deployed to at least 33 hosts in the documented intrusion after controls were impaired.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Campaign Type** | Ongoing ransomware operations targeting unpatched on-prem SharePoint |
| **Threat Cluster Names** | Longlegs / Storm-2603 (reporting references CL-CRI-1040, CamoFei, ChamelGang) |
| **Primary Initial Access** | ToolShell-related SharePoint exploitation with web shell placement |
| **Privilege/Execution Method** | ASP.NET key theft and forged signed payload deserialization |
| **Defense Evasion** | BYOVD with vulnerable signed K7RKScan driver to disable security tooling |
| **Propagation/Deployment Pattern** | SYSVOL staging and DFS replication-assisted file distribution |

## Affected Products

- On-premises Microsoft SharePoint Server deployments that remain unpatched or insufficiently mitigated against ToolShell-related weaknesses.
- Windows Active Directory environments where lateral movement and SYSVOL/DFS replication can be abused.
- Organizations in critical infrastructure, government, telecom, and education sectors.

## Attack Scenario

1. Attacker identifies an exposed, vulnerable on-premises SharePoint server.
2. Web shell is deployed to the LAYOUTS path for persistent foothold.
3. ASP.NET machine keys are stolen and used to forge signed payloads.
4. Deserialization chain executes attacker code inside SharePoint context.
5. Additional payloads are fetched, including DLL sideloading components.
6. Reconnaissance and execution validation are performed (including Burp Collaborator checks).
7. Lateral movement expands access across domain systems.
8. BYOVD tooling disables AV/EDR at scale.
9. Ransomware is staged in SYSVOL and distributed using DFS replication.
10. Warlock encryption/deployment executes across multiple hosts.

## Impact Assessment

=== "Confirmed Campaign Impact"

    - At least four recently targeted organizations in reported activity windows
    - Security-control disablement attempted or achieved at high speed across dozens of hosts
    - Domain-scale ransomware delivery observed via legitimate replication workflows

=== "Potential Impact"

    - Large-scale business disruption and service outages
    - Data loss, ransomware extortion pressure, and costly recovery operations
    - Elevated exposure for critical-infrastructure and public-sector entities

=== "Criticality"

    - **Critical** due to active exploitation, domain-wide deployment behavior, and ability to disable endpoint protections before encryption

## Mitigation Strategies

1. Patch and validate SharePoint immediately.
2. Hunt for web shells and signs of SharePoint compromise in LAYOUTS and related paths.
3. Protect ASP.NET keys and monitor for forged payload/deserialization abuse patterns.
4. Detect suspicious payload staging from cloud-hosted file services and tunneling activity.
5. Block BYOVD techniques by enforcing vulnerable-driver block rules and kernel driver policies.
6. Monitor for suspicious account additions (including SharePoint-lookalike admin accounts).
7. Protect Active Directory and SYSVOL; monitor abnormal `dfsrs.exe` file propagation patterns.
8. Segment critical servers, restrict lateral movement paths, and harden administrative protocols.
9. Maintain EDR behavioral detections, not only static IOC blocking.
10. Prepare containment and recovery playbooks including rapid host isolation and staged restoration.

## Resources and References

!!! info "Public Reporting"
    - [Warlock ransomware still exploits year-old SharePoint flaws to hit critical infrastructure](https://securityaffairs.com/200304/malware/warlock-ransomware-still-exploits-year-old-sharepoint-flaws-to-hit-critical-infrastructure.html)

---

*Last Updated: October 5, 2026*
