# GitLab CVE-2026-85706 - Unauthenticated Path Traversal
![alt text](images/GitLab.png)

**CVE-2026-85706**{.cve-chip} **Path Traversal**{.cve-chip} **Unauthenticated Access**{.cve-chip} **GitLab CE/EE**{.cve-chip} **KEV-Listed**{.cve-chip}

## Overview

CVE-2026-85706 is a critical path-traversal vulnerability (CWE-22) affecting GitLab Community Edition (CE) and Enterprise Edition (EE). Public reporting indicates the issue is tied to the repository commits API and combines improper path confinement with missing authentication enforcement under vulnerable conditions.

Under those conditions, an unauthenticated remote attacker may craft HTTP requests to traverse outside intended repository paths and read arbitrary files accessible to the GitLab service account.

The risk is elevated because exploitation does not require a valid account, and researchers reported internet-wide probing soon after patch publication.

## Technical Details

### Affected API Surface

- `/api/v4/projects/{id}/repository/commits/`

### Vulnerability Mechanics

The reported issue combines two security failures:

1. Improper path confinement allowing attacker-controlled path escape beyond expected repository boundaries.
2. Missing/insufficient authentication enforcement for affected functionality under vulnerable conditions.

### Severity

- CVSS vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`
- Score: **10.0 (Critical)**

### Affected Versions

- GitLab **18.7 through 19.1.7**
- GitLab **19.2.0 through 19.2.5**
- GitLab **19.3.0 through 19.3.1**

### Fixed Versions

- **19.1.8**
- **19.2.6**
- **19.3.2**

### Exploitation and Exposure Context

- Researchers observed rapid internet-wide probing after fixes were released.
- A key reported prerequisite is presence of at least one public project on the GitLab instance.
- CISA added CVE-2026-85706 to KEV with a remediation deadline of September 14, 2026.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **CVE** | CVE-2026-85706 |
| **Weakness** | CWE-22 (Path Traversal) |
| **Attack Prerequisite** | Publicly reachable GitLab API and at least one public project (reported) |
| **Authentication Requirement** | None under vulnerable conditions |
| **Primary Impact** | Arbitrary file read / information disclosure |
| **Secondary Risk** | Credential/token theft enabling follow-on compromise |
| **CVSS v3.1** | 10.0 (Critical) |
| **Patched Versions** | 19.1.8, 19.2.6, 19.3.2 |
| **KEV Status** | Listed by CISA |

## Affected Products

- GitLab CE and EE instances in vulnerable version ranges.
- Internet-facing self-managed GitLab deployments with public project exposure.
- CI/CD environments where secrets are accessible from server-side file contexts.

## Attack Scenario

1. Attacker identifies a publicly reachable vulnerable GitLab instance.
2. Attacker sends unauthenticated crafted request(s) to the repository commits API.
3. Path traversal allows read access outside intended repository boundaries.
4. Sensitive files may be disclosed (configuration files, access tokens, SSH keys, database credentials, CI/CD secrets).
5. Stolen secrets can be used for secondary compromise in CI/CD, cloud, Kubernetes, or internal systems.

## Impact Assessment

=== "Primary Confirmed Vulnerability Impact"

    - Unauthenticated arbitrary file-read capability under vulnerable conditions
    - Exposure of sensitive server-resident files accessible to GitLab service context

=== "Potential Follow-on Impact"

    - Credential and token abuse for account takeover or privilege expansion
    - CI/CD runner or pipeline manipulation
    - Unauthorized access to cloud, Kubernetes, and connected internal systems
    - Possible source-code integrity risk via compromised credentials

=== "Operational Risk Context"

    - Rapid post-disclosure scanning/probing increases exploitation likelihood for exposed systems
    - KEV listing indicates elevated urgency for remediation and validation

## Mitigation Strategies

### Immediate Patching

- Upgrade immediately to fixed versions: **19.1.8**, **19.2.6**, or **19.3.2** as appropriate.
- Prioritize internet-facing self-managed GitLab instances.

### Assume Potential Exposure

- Treat exposed vulnerable instances as potentially compromised if not patched promptly.
- Perform compromise assessment even after upgrade.

### Log Review and Detection

- Review HTTP/API logs for suspicious requests targeting:
  - `/api/v4/projects/{id}/repository/commits/`
- Investigate anomalous path-related request patterns and file-access behavior.

### Secrets and Access Hygiene

- Rotate potentially exposed credentials and secrets, including:
  - API tokens and access tokens
  - SSH keys
  - Database credentials
  - CI/CD variables and runner secrets
  - Cloud/Kubernetes credentials

### Post-Compromise Hunting

- Audit CI/CD pipelines, runners, and project settings for unauthorized changes.
- Hunt for lateral movement or abnormal credential use following suspected disclosure.
- Preserve logs and forensic artifacts before cleanup actions.

## Resources and References

!!! info "Public Reporting and Advisories"
    - [GitLab CVE-2026-85706: One HTTP Request, No Authentication, Full File Read - Exploited Within 24 Hours](https://securityaffairs.com/198945/hacking/gitlab-cve-2026-85706-one-http-request-no-authentication-full-file-read-exploited-within-24-hours.html)
    - [GitLab security advisory (AV26-917) - Canadian Centre for Cyber Security](https://www.cyber.gc.ca/en/alerts-advisories/gitlab-security-advisory-av26-917)
    - [Rapid Reaction: GitLab Path Traversal Vulnerability (CVE-2026-85706) | watchTowr](https://watchtowr.com/resources/rapid-reaction-gitlab-critical-path-traversal-vulnerability-cve-2026-85706/)
    - [One unauthenticated request reads any file on the GitLab server, and the patch taught attackers how | Root Notes](https://rootnotes.in/article/gitlab-cve-2026-85706-one-request-reads-any-file-on-the-server)
    - [CVE-2026-85706 - GitLab: unauthenticated arbitrary file read via the repository commits API · GPU VulnDB](https://gpuvulndb.org/vuln/CVE-2026-85706)

---

*Last Updated: September 14, 2026*