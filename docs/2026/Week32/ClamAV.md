# Cisco Warns of Seven ClamAV Flaws, Two With Public PoCs
![alt text](images/ClamAV.png)

**CVE-2026-20337**{.cve-chip} **CVE-2026-20338**{.cve-chip} **ClamAV Parser Flaws**{.cve-chip} **DoS Risk**{.cve-chip} **Cisco Secure Endpoint**{.cve-chip}

## Overview

Cisco disclosed seven ClamAV vulnerabilities affecting the Secure Endpoint Connector. The flaws exist in ClamAV parsers responsible for processing ZIP, GPT, PESpin, PDF, Mach-O, and XAR formats.

An unauthenticated remote attacker could submit a specially crafted file for scanning and potentially terminate the ClamAV scanning process, causing a denial-of-service (DoS) condition.

## Technical Details

CVE-2026-20337 involves improper boundary checking in the ZIP parser and can result in an out-of-bounds write. CVE-2026-20338 involves improper memory handling in ZIP processing.

Additional vulnerabilities impact GPT, PDF, Mach-O, and XAR parsing and involve memory corruption or improper boundary handling. Cisco assigns CVSS vector AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H, indicating remote exploitation without authentication or user interaction, with high availability impact.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Advisory Scope** | Seven ClamAV vulnerabilities in Cisco Secure Endpoint Connector context |
| **Key CVEs Highlighted** | CVE-2026-20337, CVE-2026-20338 |
| **Vulnerability Class** | Boundary-checking and memory-handling flaws in file parsers |
| **Affected Parser Formats** | ZIP, GPT, PESpin, PDF, Mach-O, XAR |
| **Attack Vector** | Network-submitted file to scanning workflow |
| **Authentication Requirement** | None |
| **User Interaction Requirement** | None |
| **Primary Impact** | ClamAV process termination (DoS) |
| **CVSS Vector (Cisco)** | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H |
| **Known Public Exploit Status** | Public PoCs reported for two ZIP-related vulnerabilities |

## Affected Products

- Cisco Secure Endpoint Connector components using vulnerable ClamAV parsing paths
- ClamAV deployments prior to fixed release 1.5.4 in applicable environments
- Windows connector environments where scanner process privilege context can increase operational risk
- File-scanning workflows that ingest untrusted archives and document formats

## Attack Scenario

1. Attacker crafts a malicious archive or file targeting a vulnerable parser.
2. The file is sent or uploaded through a channel that triggers Cisco Secure Endpoint or ClamAV scanning.
3. Vulnerable parser code processes malformed content.
4. Memory corruption or boundary-handling failure occurs.
5. ClamAV scanning process terminates unexpectedly.
6. Malware-scanning and endpoint-protection visibility is disrupted.
7. Attacker benefits from degraded detection coverage while malicious activity proceeds.

## Impact Assessment

=== "Integrity"

    - No primary evidence of direct integrity manipulation was disclosed for these bugs
    - Defensive integrity degrades indirectly when scanning services crash and controls are bypassed
    - Security operations decisions may be impacted by reduced trust in scan coverage during outages

=== "Confidentiality"

    - No direct confidentiality loss is the main demonstrated effect in current reporting
    - Reduced malware detection can indirectly expose sensitive systems to follow-on compromise
    - Interrupted scanning may delay detection of payloads intended for data theft stages

=== "Availability"

    - Primary demonstrated impact is denial of service via ClamAV process termination
    - Malware scanning operations can be interrupted, reducing endpoint protection continuity
    - Risk is more significant on Windows where the scanner process may run with elevated privileges

## Mitigation Strategies

### Immediate Remediation

- Apply Cisco security updates for affected Secure Endpoint Connector versions as soon as available.
- Upgrade ClamAV components to version 1.5.4 where applicable.
- Prioritize patch rollout for Windows endpoints due to higher process-privilege risk.

### Exposure Reduction

- Identify all connectors and scanning paths that process untrusted archives and documents.
- Validate that update channels are functioning for endpoint connectors and signature engines.
- Ensure unsupported or delayed-update endpoints are isolated from high-risk ingestion flows.

### Monitoring and Detection

- Monitor for abnormal ClamAV process crashes, restarts, or scan-service instability.
- Investigate suspicious archive or file submissions that correlate with scanner termination events.
- Track endpoint telemetry for detection gaps following scan-engine failures.

### Response Actions

- Treat repeated scan-process crashes as potential exploitation attempts and trigger incident triage.
- Increase compensating controls temporarily if patching is delayed.
- Confirm remediation by validating connector and ClamAV versions after deployment.

## Resources and References

!!! info "Public Reporting"
    - [Cisco Warns of Seven ClamAV Flaws, Two With Public PoCs](https://securityaffairs.com/196973/security/cisco-warns-of-seven-clamav-flaws-two-with-public-pocs.html)
    - [Cisco Patches Firewall Zero-Day Exploited for DoS Attacks - SecurityWeek](https://www.securityweek.com/cisco-patches-firewall-zero-day-exploited-for-dos-attacks/)
    - [Cisco warns of high-severity ClamAV flaws with public exploits](https://www.bleepingcomputer.com/news/security/cisco-warns-of-high-severity-clamav-flaws-with-public-exploits/)

---

*Last Updated: August 12, 2026*
