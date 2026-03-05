# Mail2Shell Zero-Click Attack Lets Hackers Hijack FreeScout Mail Servers
![alt text](images/mail2shell.png)

**CVE-2026-28289**{.cve-chip}  **Mail2Shell**{.cve-chip}  **Zero-Click RCE**{.cve-chip}  **Unicode Bypass**{.cve-chip}

## Overview
Security researchers reported a critical FreeScout vulnerability dubbed **Mail2Shell** that can allow attackers to execute arbitrary commands by sending a specially crafted email attachment. The attack abuses filename handling during incoming email attachment processing to bypass protections and enable server-side code execution.

The flaw is described as a bypass of a previously patched issue and can lead to full helpdesk server compromise without user interaction when vulnerable versions process attacker-controlled inbound mail.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Primary CVE** | CVE-2026-28289 |
| **Related Context** | Patch bypass of earlier FreeScout issue (CVE-2026-27636 context) |
| **Vulnerability Type** | Filename validation bypass leading to unauthenticated remote code execution |
| **Affected Component** | FreeScout incoming email attachment processing |
| **Bypass Method** | Prepending zero-width Unicode character (e.g., U+200B) to blocked filenames |
| **Abused File Type** | `.htaccess` (server behavior manipulation), followed by web-shell execution path |
| **Authentication Required** | None (crafted email delivery path) |
| **Patched Version** | FreeScout v1.8.207 or later |

## Affected Products
- FreeScout deployments handling inbound email to support mailboxes
- Internet-reachable helpdesk instances with automated attachment ingestion enabled
- Apache-backed deployments where `.htaccess` behavior can be abused
- Organizations storing sensitive support communications and attachments in FreeScout
- Status: Critical patch available; immediate upgrade recommended

## Technical Details

### Attachment Processing Path
- FreeScout auto-parses incoming email and stores attachments.
- Validation attempts to block dangerous attachment names (for example `.htaccess`).

### Filename Validation Bypass
- Attacker prepends an invisible zero-width character (such as `U+200B`) before blocked filenames.
- Example conceptual payload: `[Zero-Width-Space].htaccess`.
- During validation, the filename appears acceptable; later normalization/processing can strip the invisible character and yield `.htaccess`.

### Configuration Abuse to RCE
- Uploaded `.htaccess` can alter Apache behavior in attachment-reachable paths.
- Attacker then uploads or triggers malicious script execution (e.g., PHP web shell behavior).
- Result: unauthenticated remote command execution and server takeover.

## Attack Scenario
1. **Target Discovery**:
    - Attacker identifies a publicly reachable FreeScout support mailbox/workflow.

2. **Weaponized Email Delivery**:
    - Crafted email includes malicious attachment filename using hidden Unicode character trick.

3. **Automatic Processing**:
    - FreeScout ingests and stores attachment without requiring operator interaction.

4. **Validation Bypass Realization**:
    - Filename protections are bypassed and dangerous file is effectively written.

5. **Execution Enablement**:
    - Apache behavior is modified via `.htaccess` abuse.

6. **Server Compromise**:
    - Attacker uploads or triggers malicious script/web shell execution and gains remote control.

## Impact Assessment

=== "Integrity"
    * Full FreeScout server compromise via unauthenticated command execution
    * Unauthorized modification of helpdesk files/configurations
    * Persistent backdoor installation and operational tampering risk

=== "Confidentiality"
    * Exposure of support tickets, customer communications, and attachments
    * Potential database exfiltration and credential/session data theft
    * Leakage of internal operational and customer-sensitive information

=== "Availability"
    * Service instability or outage from malicious post-exploitation actions
    * Potential ransomware staging from compromised helpdesk infrastructure
    * Elevated risk of lateral movement into broader internal systems

## Mitigation Strategies

### Immediate Remediation
- Upgrade FreeScout to `v1.8.207` or later immediately
- Validate that the environment is not running vulnerable pre-patch/bypassable versions

### Web Server Hardening
- Disable or tightly restrict `.htaccess` overrides where possible
- Isolate upload/attachment paths from executable contexts

### Attachment Security Controls
- Restrict allowed attachment extensions and enforce strict server-side validation
- Detect/normalize hidden Unicode characters in filenames before storage
- Block suspicious filenames including `.htaccess`, executable scripts, and deceptive Unicode variants

### Monitoring and Detection
- Monitor attachment directories for anomalous files such as `.htaccess`, `.php`, and unicode-obfuscated names
- Alert on unusual write/execute patterns in attachment storage paths
- Deploy WAF rules and server logging tuned for malicious upload/execution behavior

### Architectural Risk Reduction
- Run helpdesk applications in isolated containers/segments
- Enforce least-privilege permissions on web and mail-processing services

## Resources and References

!!! info "Open-Source Reporting"
    - [Mail2Shell zero-click attack lets hackers hijack FreeScout mail servers](https://www.bleepingcomputer.com/news/security/mail2shell-zero-click-attack-lets-hackers-hijack-freescout-mail-servers/)
    - [Critical FreeScout Vulnerability Leads to Full Server Compromise - SecurityWeek](https://www.securityweek.com/critical-freescout-vulnerability-leads-to-full-server-compromise/)
    - [NVD - CVE-2026-28289](https://nvd.nist.gov/vuln/detail/CVE-2026-28289)
    - [FreeScout 1.8.206 - Patch Bypass for CVE-2026-27636 via Zero-Width Space Character Leads to Unauthenticated Remote Code Execution · Advisory · freescout-help-desk/freescout](https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-5gpc-65p8-ffwp)

---

*Last Updated: March 5, 2026* 
