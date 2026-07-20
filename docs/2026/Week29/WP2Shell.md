# WP2Shell WordPress Vulnerabilities Exploited in the Wild
![alt text](images/WP2Shell.png)

**CVE-2026-63030**{.cve-chip} **CVE-2026-60137**{.cve-chip} **Pre-Auth RCE**{.cve-chip} **WordPress Core**{.cve-chip} **Active Exploitation**{.cve-chip}

## Overview

WP2Shell is the name given to a WordPress core exploit chain combining two vulnerabilities that can enable anonymous, pre-authentication remote code execution on default WordPress installations.

Public proof-of-concept code is available and multiple security vendors report in-the-wild exploitation, making patching urgent. WordPress has released fixes and enabled broad auto-update push behavior, but administrators are advised to verify patch status manually.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Core CVEs** | CVE-2026-63030, CVE-2026-60137 |
| **CVE-2026-63030** | REST API batch-route confusion flaw in WordPress core |
| **CVE-2026-60137** | SQL injection in WordPress core (`WP_Query author__not_in`) |
| **Primary Chain Outcome** | Anonymous pre-authentication remote code execution |
| **Preconditions** | None on stock vulnerable installs (no plugin requirement, no account needed) |
| **Typical Attack Paths** | `/wp-json/batch/v1` and `rest_route=/batch/v1` |
| **Observed Post-Exploitation** | Rogue admin creation, web shell deployment, malware installation |
| **Patch Releases** | WordPress 6.9.5 and 7.0.2 (also included in 7.1 Beta 2) |
| **Threat Activity** | Public PoCs + active exploitation reported by multiple security firms |

## Affected Products

- WordPress core installations on vulnerable 6.9.x and 7.0.x branches prior to patched releases
- Internet-exposed WordPress sites with accessible REST API batch endpoints
- Organizations hosting multiple WordPress instances with inconsistent patch governance

## Attack Scenario

1. Attackers scan for WordPress instances exposing vulnerable version fingerprints and REST API routes.
2. A crafted request abuses batch-route confusion (CVE-2026-63030) to manipulate endpoint processing.
3. SQL injection (CVE-2026-60137) is chained to escalate control over query behavior and privilege context.
4. Attackers achieve unauthenticated remote code execution, deploy web shells, and create rogue administrator accounts.
5. Compromised sites are used for data theft, defacement, further malware distribution, or as infrastructure in broader campaigns.

## Impact Assessment

=== "Integrity"

    - Full site compromise with unauthorized administrator creation and content manipulation
    - Web shell deployment enables persistent attacker control and follow-on payload execution
    - Potential tampering with plugins, themes, and update channels

=== "Confidentiality"

    - Exposure of customer records, admin data, and backend secrets stored in WordPress or connected systems
    - Theft of credentials and API keys from configuration and plugin storage
    - Increased risk of broader compromise where WordPress shares infrastructure with internal systems

=== "Availability"

    - Site outages, defacement, and service degradation from malicious code execution
    - Recovery downtime due to forensic triage, malware cleanup, and restoration from backups
    - Repeat compromise risk if patching and hardening are incomplete

## Mitigation Strategies

### Immediate Actions

- Update WordPress core immediately to patched versions (6.9.5, 7.0.2, or later)
- Do not rely solely on assumed auto-updates; verify installed version manually in admin and filesystem
- Remove unauthorized admin accounts and unknown plugins/themes after compromise review

### Short-term Measures

- Add WAF/reverse-proxy protections for suspicious traffic targeting batch REST routes
- Consider temporary restrictions on unauthenticated REST API access where operationally feasible
- Validate backups and prepare clean rollback points before and after patch deployment

### Monitoring & Detection

- Review logs for anomalous requests to `/wp-json/batch/v1` and `rest_route=/batch/v1`
- Hunt for web shells, unexpected file changes, and newly created privileged accounts
- Use version exposure checks (for example wp2shell.com guidance) to confirm remediation status

### Long-term Solutions

- Implement continuous patch SLAs for CMS core and dependency updates
- Apply least privilege on hosting layers and isolate WordPress from sensitive internal systems
- Maintain incident response playbooks for rapid restoration and post-exploitation eradication

## Resources and References

!!! info "Public Reporting"
    - [WP2Shell WordPress Vulnerabilities Exploited in the Wild](https://www.securityweek.com/wp2shell-wordpress-vulnerabilities-exploited-in-the-wild/)
    - [Attackers can take over WordPress sites using newly released WP2Shell exploits](https://securityaffairs.com/195597/hacking/attackers-can-take-over-wordpress-sites-using-newly-released-wp2shell-exploits.html)
    - [WordPress Core WP2Shell RCE flaws get public exploits, patch now](https://www.bleepingcomputer.com/news/security/wordpress-core-wp2shell-rce-flaws-get-public-exploits-patch-now/)
    - [New WP2Shell WordPress Core Flaw Lets Attackers Hijack Sites](https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html)
    - [WP2Shell Exposure Check](https://wp2shell.com/)

---

*Last Updated: July 20, 2026*
