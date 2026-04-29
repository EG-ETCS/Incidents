# Critical GitHub Vulnerability Exposed Millions of Repositories (CVE-2026-3854)
![alt text](images/GitHub.png)

**CVE-2026-3854**{.cve-chip} **Remote Code Execution**{.cve-chip} **Command Injection**{.cve-chip} **Supply Chain Risk**{.cve-chip}

## Overview

CVE-2026-3854 is a critical command injection vulnerability in GitHub's internal `git push` processing pipeline, carrying a CVSS score of 8.7. An attacker with ordinary push access to any repository can inject malicious push option values that bypass sanitization in inter-service headers, ultimately overriding environment variables and hook execution paths to achieve remote code execution on backend servers. On GitHub Enterprise Server (GHES), successful exploitation yields full instance compromise; on GitHub.com, Wiz Research confirmed RCE on multi-tenant shared storage nodes, exposing data from millions of repositories.

Discovered by Wiz Research in March 2026 and reported via GitHub's bug bounty program, GitHub validated and hot-patched GitHub.com in under two hours. No evidence of exploitation in the wild was found.

## Technical Specifications

| Attribute | Details |
|---|---|
| **CVE** | CVE-2026-3854 |
| **CVSS Score** | 8.7 (Critical) |
| **Vulnerability Type** | Command Injection / Improper Neutralization of Input in Internal Service Headers |
| **Affected Products** | GitHub Enterprise Server (GHES) all versions before fix; GitHub.com (patched) |
| **Fixed GHES Versions** | 3.14.25, 3.15.20, 3.16.16, 3.17.13, 3.18.7, 3.19.4 (or later) |
| **Attack Prerequisite** | Authenticated push access to any repository on the target |
| **Root Cause** | User-supplied `git push` options embedded in internal service headers without sanitization |
| **Wild Exploitation** | None confirmed |
| **Discovered By** | Wiz Research (reported March 4, 2026) |

## Affected Products

- **GitHub Enterprise Server (GHES)** — all versions prior to the fixed releases listed above
- **GitHub.com / Enterprise Cloud** — patched by GitHub within two hours of report; no customer action required

## Attack Scenario

1. Attacker authenticates to a GitHub instance with developer-level push access to any repository — no elevated privileges required
2. A `git push` is crafted with malicious push options (e.g., `git push -o key=value`) containing a delimiter character that splits the value into multiple injected header fields
3. GitHub's backend embeds the user-supplied options into an internal service header without adequate escaping, causing the injected fields to be parsed as legitimate metadata by downstream microservices
4. Downstream services consume the spoofed header fields, enabling the attacker to: toggle feature flags (e.g., enable custom hook execution on GitHub.com), override environment variables (e.g., sandbox restrictions), and redirect the hook directory via path traversal to an attacker-controlled location
5. When the push is processed, the backend executes hooks or scripts from the attacker-controlled path as the git service account — achieving RCE on the storage or application node
6. On GHES: attacker gains full control of the instance — all repositories, secrets, configuration, and CI/CD pipelines
7. On GitHub.com: attacker achieves RCE on shared multi-tenant storage nodes, with visibility into repositories hosted across that node

## Impact

=== "Technical Impact"

    - Full remote code execution on GHES backend servers with developer-level push access only
    - On GitHub.com: confirmed RCE on shared storage nodes despite custom hooks normally being disabled
    - Access to all repositories, secrets, tokens, and CI/CD configuration on compromised instances
    - Ability to tamper with pipelines, inject backdoors into codebases, and poison release artifacts

=== "Business Impact"

    - GHES customers face complete instance compromise — source code, credentials, and build infrastructure at risk
    - GitHub.com multi-tenancy means a single exploit attempt could expose data from millions of repositories
    - Incident response burden for organizations auditing push logs and hook behavior around the disclosure window

=== "Supply Chain Impact"

    - GitHub is foundational to global software supply chains; platform-level RCE translates to downstream risk for thousands of vendors and open-source projects
    - Highlights internal microservice protocols as a critical attack surface when carrying user-controlled input
    - Demonstrates that low-privilege access (push rights) can have catastrophic blast radius in complex platforms

## Mitigations

### For GitHub Enterprise Server Admins

- **Patch immediately** — upgrade to fixed GHES versions: `3.14.25`, `3.15.20`, `3.16.16`, `3.17.13`, `3.18.7`, `3.19.4`, or later
- Audit who holds push access to repositories on internet-facing GHES instances; apply least-privilege principles
- Review `git push` operation logs for malformed or unusual push options, particularly between March–April 2026
- Investigate for anomalous hook behavior or unexpected processes running as the git service account
- Confine hook execution to tightly sandboxed environments (containers, seccomp, AppArmor) even after patching

### For GitHub.com / Enterprise Cloud Users

- No software patch required — GitHub has already fixed and redeployed the fix
- Enforce least-privilege access controls on sensitive repositories, especially release and protected branches
- Monitor critical repositories for unexpected commits, configuration changes, or CI/CD modifications

### Engineering Lessons

- Internal service protocols carrying user-controlled data must be treated as untrusted; centralize sanitization and enforce strict delimiter and encoding rules
- Apply defense-in-depth around hook execution — even if header metadata is compromised, hooks should run in tightly constrained, isolated environments

## Resources

!!! info "Open-Source Reporting"
    - [CVE-2026-3854: GitHub Flaw Enables Remote Code Execution — SecurityAffairs](https://securityaffairs.com/191434/security/cve-2026-3854-github-flaw-enables-remote-code-execution.html)
    - [Securing the Git Push Pipeline: Responding to a Critical RCE Vulnerability — GitHub Blog](https://github.blog/security/securing-the-git-push-pipeline-responding-to-a-critical-remote-code-execution-vulnerability/)
    - [GitHub RCE Vulnerability CVE-2026-3854 — Wiz Research](https://www.wiz.io/blog/github-rce-vulnerability-cve-2026-3854)
    - [Discussion — Hacker News](https://news.ycombinator.com/item?id=47936479)
    - [Researchers Discover Critical GitHub Vulnerability — The Hacker News](https://thehackernews.com/2026/04/researchers-discover-critical-github.html)

---

*Last Updated: April 29, 2026*