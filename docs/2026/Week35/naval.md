# Exploitation against Philippine nuclear research and naval-support organizations
![alt text](images/naval.png)

**Cyber Espionage**{.cve-chip} **Nuclear Research Exposure**{.cve-chip} **Naval Support Targeting**{.cve-chip} **CVE-2023-49105**{.cve-chip} **CVE-2024-28000**{.cve-chip}

## Overview

A suspected Chinese-speaking threat actor breached a Philippine nuclear research organization and a marine engineering and shipbuilding company supporting the Philippine Navy by exploiting old, publicly known vulnerabilities in internet-facing ownCloud and WordPress systems. The operation was uncovered after Hunt.io identified exposed attacker infrastructure containing tools, logs, and stolen data.

The most sensitive confirmed impact concerns the nuclear research organization, where accessed data reportedly included nuclear-material records, reactor-component information, fuel inventories, radiation-safety records, strategic planning documents, personnel data, credentials, and cryptographic key material. Public reporting frames this as a targeted cyber-espionage and data-theft campaign, not an announced nuclear safety or operations disruption event.

## Technical Details

### Affected Organizations

- A Philippine nuclear research organization (name not publicly disclosed in cited reporting).
- A Philippine marine engineering and shipbuilding company that supports the Philippine Navy (also not publicly named).

### Discovery

- Hunt.io reported an exposed ownCloud server in Amsterdam assessed as attacker infrastructure.
- The exposed directory reportedly contained 1,310 files totaling nearly 1.2 GB, including scripts, logs, tools, and intrusion-linked artifacts.
- Recovered nuclear-target data reportedly included 176 files totaling approximately 372 MB.
- Attacker logs indicated a potentially larger collection near 9 GB, but this amount remains unverified attacker-record data rather than independently confirmed exfiltration volume.

### Primary Vulnerability - ownCloud

- **CVE-2023-49105**: ownCloud WebDAV API authentication bypass (CVSS 9.8).
- Reported affected range: ownCloud core 10.6.0 through 10.13.0.
- Reported fix baseline: 10.13.1; multiple reports recommend 10.13.3 or later plus all relevant vendor fixes.
- The flaw affects pre-signed URL behavior when the signing secret/key is empty, enabling crafted accepted WebDAV requests for known usernames without password authentication.

### ownCloud Exploitation Behavior

- The actor reportedly used five custom Python scripts to exploit CVE-2023-49105 and retrieve files account by account.
- Scripts used WebDAV directory requests for enumeration and introduced random delays between downloads.
- Reported activity enabled unauthenticated retrieval and potentially modification/deletion for accessible file contexts.

### Secondary Vulnerability - WordPress LiteSpeed Cache

- **CVE-2024-28000**: unauthenticated privilege escalation in LiteSpeed Cache plugin versions before 6.4.
- Reported abuse allowed derivation of plugin security hash and creation of a WordPress administrator account through the REST API.
- Reporting also mentions XML-RPC credential brute-force activity against the naval contractor environment.

### Tools and Infrastructure

- Reported tooling included custom Python scripts, Sliver, Metasploit, and Mettle.
- Exposed host in reporting: 31.58.209[.]241; treat as historical context and validate with current intelligence before enforcement actions.

### Attribution

- Suspected Chinese-speaking actor based on researcher analysis and observed operator language.
- No named threat group, government agency, or individual has been publicly confirmed.

### Exploitation Status

- Confirmed active exploitation of CVE-2023-49105 in the reported intrusion.
- Reporting states CISA added CVE-2023-49105 to the KEV catalog after the case.
- Both vulnerabilities were old and patched before this campaign timeframe.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Campaign Type** | Targeted cyber-espionage and data-theft operation |
| **Suspected Operator** | Chinese-speaking threat actor (unattributed publicly to a named group) |
| **Organization Scope** | Philippine nuclear research and naval-support maritime engineering |
| **Primary CVE** | CVE-2023-49105 (ownCloud WebDAV auth bypass, CVSS 9.8) |
| **Secondary CVE** | CVE-2024-28000 (LiteSpeed Cache privilege escalation) |
| **Exposed Infrastructure Volume** | 1,310 files, nearly 1.2 GB |
| **Recovered Nuclear Data Sample** | 176 files, approximately 372 MB |
| **Possible Larger Collection** | Around 9 GB in attacker logs (unverified) |
| **Observed Tooling** | Custom Python scripts, Sliver, Metasploit, Mettle |
| **Historical Host Indicator** | 31.58.209[.]241 |
| **Confirmed Operational Disruption** | Not publicly reported |

## Affected Products

- ownCloud deployments vulnerable to CVE-2023-49105, especially where pre-signed URL signing secret/key is empty.
- WordPress deployments using LiteSpeed Cache plugin versions before 6.4.
- WordPress instances with exposed XML-RPC and weak administrative credential controls.

## Attack Scenario

1. The operator identifies internet-facing ownCloud and WordPress systems at high-value Philippine nuclear and naval-support targets.
2. Against ownCloud, the attacker exploits CVE-2023-49105 where signing-secret conditions are vulnerable.
3. Forged pre-signed WebDAV requests are generated for known/discovered usernames.
4. Custom scripts enumerate directories and collect targeted files while using random delays to reduce obvious automation.
5. Against a separate naval-support contractor, the attacker exploits CVE-2024-28000 to create administrator access in WordPress.
6. Tools, logs, and collected artifacts are staged on exposed infrastructure later discovered by researchers.

## Impact Assessment

=== "Confirmed and Reported Impact"

    - Confirmed compromise of a Philippine nuclear research organization and a separate naval-support contractor
    - Exposure of sensitive nuclear-adjacent, personnel, strategic, and credential-related information
    - No public evidence of reactor-control compromise, OT/ICS disruption, or radioactive safety event

=== "Exposure Scope"

    - Recovered nuclear-target set: 176 files totaling approximately 372 MB
    - Exposed attacker directory: 1,310 files totaling nearly 1.2 GB
    - Larger ~9 GB figure appears in attacker logs and remains unverified as completed exfiltration

=== "Potential Follow-on Risk"

    - Credential abuse, spear-phishing, and long-term espionage operations
    - Exploitation of strategic and research data for future targeting
    - Elevated national-security risk for organizations managing critical research and defense-adjacent information

=== "Sector Relevance"

    - ownCloud is widely used for self-hosted collaboration and data exchange across government, education, research, healthcare, defense, and enterprise environments
    - WordPress with LiteSpeed Cache is common for public portals and web applications across sectors

=== "Used in Egypt"

    - Relevant technologies are used broadly in Egypt across public and private sectors
    - No public evidence indicates Egyptian organizations were directly targeted in this reported campaign
    - Organizations in Egypt operating exposed ownCloud/WordPress services should treat these vulnerabilities as high-priority patching and monitoring issues

### Criticality

- **Critical**: Confirmed exploitation of a CVSS 9.8 authentication-bypass vulnerability and exposure of sensitive nuclear and national-security-related data indicate high strategic risk even without reported OT disruption.

## Mitigation Strategies

### Patch ownCloud Immediately

- Upgrade ownCloud to patched versions (reporting cites 10.13.1 as fixed and commonly recommends 10.13.3 or later).
- Configure a strong, non-empty signing secret/key for pre-signed URL mechanisms.
- Reduce direct internet exposure of ownCloud administrative and file-sharing interfaces where possible.

### Patch LiteSpeed Cache

- Upgrade the LiteSpeed Cache plugin to version 6.4 or later.
- Review WordPress administrator accounts, preserving forensic evidence before removing unauthorized accounts.

### Investigate Historical Exposure

- Treat previously vulnerable ownCloud deployments with empty signing secrets as potentially compromised.
- Review WebDAV logs for abnormal pre-signed URL usage, broad account enumeration, and bulk file-download behavior.
- Investigate unusual directory-listing activity and unfamiliar-source access patterns.

### Rotate Exposed Secrets

- Rotate user/admin credentials, API keys, cryptographic keys, certificates, and tokens that may have been accessible through compromised systems.
- Invalidate active sessions and review service accounts, integrations, backups, and synchronized endpoints.

### Harden WordPress

- Keep WordPress core, themes, plugins, PHP, and server components fully patched.
- Restrict or disable XML-RPC when not required.
- Enforce MFA, strong unique passwords, and tightly scoped administrative network access.
- Apply WAF controls and monitor REST API activity and unexpected administrator creation.

### Reduce Exposure and Improve Monitoring

- Maintain complete inventory of internet-facing applications and remote-access services.
- Use external attack-surface monitoring for exposed ownCloud, WebDAV, and WordPress assets.
- Centralize web, app, auth, database, and file-access logs into SIEM/SOC and alert on mass-download, enumeration, unusual API use, and account-creation anomalies.

### Protect High-Value Research and National-Security Data

- Segment collaboration platforms away from sensitive research, defense, OT, and operational environments.
- Enforce least privilege, data classification, encryption, access review cycles, immutable backups, and tested incident response.
- Notify relevant national CERT, regulators, and law enforcement when national-security-related exposure is suspected.

## Resources and References

!!! info "Public Reporting"
    - [Dark Reading: Old, Unpatched Flaws Help Attackers Breach Philippine Nuclear Agency](https://www.darkreading.com/cyberattacks-data-breaches/old-unpatched-flaws-attackers-philippines-nuclear-agency)
    - [The Hacker News](https://thehackernews.com/2026/08/snowflake-github-actions-flaw-lets.html?ref=blog.netmanageit.com)
    - [Security Affairs: Philippine Nuclear and Naval Targets Hit by Suspected Chinese Operator](https://securityaffairs.com/198041/intelligence/philippine-nuclear-and-naval-targets-hit-by-suspected-chinese-operator.html)
    - [Cybersecurity News: Hackers Exploit ownCloud Vulnerability](https://cybersecuritynews.com/hackers-exploit-owncloud/)
    - [SC World Brief](https://www.scworld.com/brief/suspected-chinese-actor-targets-philippine-nuclear-and-naval-entities-using-known-vulnerabilities)

---

*Last Updated: September 03, 2026*