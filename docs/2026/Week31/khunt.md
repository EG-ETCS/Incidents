# khunt Oracle Database Post-Exploitation Toolkit Attack
![alt text](images/khunt.png)

**Oracle Database Abuse**{.cve-chip} **SQL Injection Chain**{.cve-chip} **OJVM Weaponization**{.cve-chip} **Credential Theft**{.cve-chip} **Low-Forensic Footprint**{.cve-chip}

## Overview

Researchers identified an attack chain where threat actors exploited a SQL Injection flaw in a public-facing Java web application to compromise an Oracle Database server.

Instead of deploying traditional host malware, attackers used Oracle Java features to compile and execute a custom toolkit named khunt directly inside the database, enabling command execution, host reconnaissance, file access, and credential theft with limited disk artifacts.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Initial Access** | SQL Injection in internet-facing Java application |
| **Database Abuse Primitive** | Privileged SQL statements invoking `CREATE JAVA SOURCE` |
| **Execution Environment** | Oracle embedded Java Virtual Machine (OJVM) |
| **Invocation Path** | Java classes exposed through PL/SQL wrapper procedures |
| **Observed Toolkit Functions** | Command execution, file browsing, ZIP extraction, credential collection |
| **Host Recon Commands Seen** | `cmd.exe /c whoami`, `tasklist /svc` |
| **Credential-Theft Method** | PowerShell/Windows utilities copying SAM, SYSTEM, and SECURITY hives |
| **Forensic Evasion Characteristic** | Toolkit logic residing in DB objects rather than conventional disk malware |

## Affected Products

- Public-facing Java applications with exploitable SQL Injection flaws
- Oracle Database deployments with OJVM enabled and overly permissive privileges
- Windows-hosted Oracle environments susceptible to OS command abuse from DB context
- Enterprise systems where database service accounts can access sensitive host resources

## Attack Scenario

1. Attacker discovers SQL Injection in an internet-facing Java application.
2. Injection enables database-level command execution with elevated SQL privileges.
3. Malicious Java source is uploaded/compiled via `CREATE JAVA SOURCE` inside Oracle.
4. PL/SQL wrappers invoke embedded Java classes from database context.
5. Toolkit executes OS commands under Oracle service-account privileges.
6. Host data, files, and credential artifacts (including registry hives) are collected.
7. Stolen credentials support persistence, escalation, and potential lateral movement.

## Impact Assessment

=== "Integrity"

    - Database-trusted Java objects can be repurposed for unauthorized post-exploitation control
    - Attackers can execute system commands and manipulate host/database state from inside Oracle
    - Abuse of native DB extensibility features undermines traditional trust assumptions

=== "Confidentiality"

    - Theft risk includes Windows password hashes and Oracle-related credentials
    - Sensitive local/server files may be accessed and exfiltrated
    - Database-resident tooling can reduce early detection and extend dwell time

=== "Availability"

    - Command execution on DB hosts can degrade or disrupt critical database-dependent services
    - Incident containment may require emergency revocation of Java/privileged capabilities
    - Recovery complexity increases when persistence is embedded in schema objects

## Mitigation Strategies

### Application and Input Security

- Eliminate SQL Injection through parameterized queries and strict input validation.
- Apply secure coding review and regression testing for all database-facing endpoints.

### Privilege and Feature Hardening

- Enforce least privilege on database accounts and application schemas.
- Restrict or disable unnecessary Oracle Java capabilities (`CREATE JAVA SOURCE`) where possible.
- Limit ability to create/execute privileged PL/SQL wrappers and external-call pathways.

### Detection and Monitoring

- Monitor Oracle audit logs for creation/modification of Java source objects and wrapper procedures.
- Alert on DB process chains spawning OS tools (`cmd.exe`, `powershell.exe`, etc.).
- Perform routine inventory/audit of Oracle Java objects and privilege grants for unauthorized additions.

### Defensive Architecture

- Deploy WAF protections to reduce SQL Injection exploitation attempts.
- Continuously monitor for anomalous database activity, privilege escalation, and suspicious post-exploitation behavior.
- Segment database hosts and constrain service-account OS permissions to minimize blast radius.

## Resources and References

!!! info "Public Reporting"
    - [Attackers Compile khunt Inside Oracle to Turn SQL Injection Into Windows SYSTEM Access](https://thehackernews.com/2026/08/attackers-compile-khunt-inside-oracle.html)
    - [Hackers run khunt post-exploitation toolkit from Oracle database](https://www.bleepingcomputer.com/news/security/hackers-run-khunt-post-exploitation-toolkit-from-oracle-database/amp/)

---

*Last Updated: August 6, 2026*
