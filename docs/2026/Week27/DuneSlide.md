# DuneSlide – Critical Cursor AI IDE Prompt Injection Vulnerabilities
![alt text](images/DuneSlide.png)

**CVE-2026-50548**{.cve-chip} **CVE-2026-50549**{.cve-chip} **Prompt Injection**{.cve-chip} **Sandbox Escape**{.cve-chip} **AI IDE RCE**{.cve-chip}

## Overview

Security researchers from Cato AI Labs disclosed two critical vulnerabilities in the Cursor AI code editor that allow attackers to chain an indirect prompt injection with a sandbox escape, resulting in arbitrary operating system command execution. The vulnerabilities, collectively named DuneSlide, affect Cursor versions prior to 3.0 and were patched in Cursor 3.0.

![alt text](images/DuneSlide1.png)

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **CVE IDs** | CVE-2026-50548, CVE-2026-50549 |
| **Vulnerability Type** | Prompt Injection + Sandbox Escape leading to OS Command Execution |
| **CVSS Score** | Not publicly disclosed at the time of reporting |
| **Attack Vector** | Remote content ingestion through AI-assisted workflows (repositories, docs, MCP responses) |
| **Authentication** | None required by attacker |
| **Complexity** | Low to Medium |
| **User Interaction** | Required (developer opens or processes attacker-controlled content in Cursor) |
| **Affected Versions** | Cursor versions prior to 3.0 |
| **Patched Version** | Cursor 3.0 |

## Affected Products

- Cursor AI IDE versions earlier than 3.0
- Developer workstations where Cursor AI assistant can process untrusted external content
- Environments that allow broad AI-agent execution permissions and trusted third-party MCP integrations

## Attack Scenario

1. An attacker publishes a malicious GitHub repository, documentation page, or MCP server response containing hidden prompt injection instructions.
2. A developer opens the repository or documentation using Cursor.
3. Cursor's AI assistant automatically analyzes the malicious content.
4. The embedded instructions manipulate the AI agent into escaping its execution restrictions.
5. Arbitrary operating system commands are executed on the victim's machine.
6. The attacker steals credentials, source code, API keys, or installs malware for persistence.

## Impact Assessment

=== "Integrity"

    - Unauthorized command execution can modify source code, local configurations, and build artifacts
    - Attackers may implant backdoors or tamper with software projects and CI/CD workflows
    - Compromised developer endpoints can become a launch point for internal supply chain manipulation

=== "Confidentiality"

    - Theft of SSH keys, GitHub tokens, cloud credentials, API secrets, and proprietary source code
    - Exposure of sensitive local files, environment variables, and enterprise access tokens
    - Exfiltration risks increase when malicious commands run under developer user privileges

=== "Availability"

    - Malicious commands can disrupt developer environments and break project dependencies
    - Malware installation may degrade endpoint performance and require incident response downtime
    - Enterprise development operations can be interrupted during containment and credential rotation

## Mitigation Strategies

### Immediate Actions

- Upgrade immediately to Cursor 3.0 or later
- Revoke and rotate potentially exposed credentials (SSH keys, tokens, API keys)
- Isolate and investigate developer systems suspected of processing malicious prompt content

### Short-term Measures

- Treat all AI-consumed external content as untrusted
- Restrict permissions granted to AI coding agents and tool execution surfaces
- Carefully review and limit trusted MCP servers and third-party integrations

### Monitoring & Detection

- Deploy EDR solutions to detect suspicious shell or script execution from developer endpoints
- Monitor unusual command-line activity and outbound traffic after AI assistant interactions
- Alert on anomalous access to source repositories, secrets stores, and cloud control planes

### Long-term Solutions

- Apply the principle of least privilege to developer workstations and local tooling
- Move sensitive credentials to managed secret stores and reduce local secret persistence
- Train developers on prompt injection risks and AI-assisted secure development practices

## Resources and References

!!! info "Public Reporting"
    - [Critical Cursor Flaws Could Let Prompt Injection Escape Sandbox and Run Commands](https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html)
    - [Critical Cursor AI Code Editor Flaws Could Lead to OS-Level Remote Code Execution - SecurityWeek](https://www.securityweek.com/critical-cursor-ai-ide-flaws-could-lead-to-os-level-remote-code-execution/)
    - [Sandbox bypass flaws in Cursor IDE highlight prompt injection as an RCE vector | CSO Online](https://www.csoonline.com/article/4191923/sandbox-bypass-flaws-in-cursor-ide-highlight-prompt-injection-as-an-rce-vector.html)
    - [Prompt injection as an RCE vector in AI editors | Hard2bit](https://hard2bit.com/en/blog/prompt-injection-rce-ai-code-editors-cursor-duneslide/)

---

*Last Updated: July 5, 2026*
