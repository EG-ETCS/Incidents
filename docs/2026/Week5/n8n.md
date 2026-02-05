# CVE-2026-25049 – Critical Remote Code Execution in n8n Workflow Expressions

**CVE-2026-25049**{.cve-chip}  **Remote Code Execution**{.cve-chip}  **Workflow Automation**{.cve-chip}

## Overview
A critical security flaw in the n8n workflow automation platform allows authenticated users with workflow creation or editing privileges to execute arbitrary system commands on the host server. The issue stems from insufficient sanitization of workflow expressions, enabling attackers to escape the intended execution sandbox and run malicious JavaScript that reaches the underlying operating system. When combined with public webhooks, the vulnerability can be triggered remotely, potentially compromising the entire automation infrastructure and connected systems.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **CVE ID** | CVE-2026-25049 |
| **Vulnerability Type** | Remote Code Execution via Expression Injection |
| **CVSS Score**| 9.4 (Critical) |
| **Attack Vector** | Network |
| **Authentication** | Required (workflow creation/editing rights) |
| **Complexity** | Low |
| **User Interaction** | Not Required |
| **Affected Component** | Workflow expression evaluation engine |

## Affected Products
- n8n versions prior to 1.123.17
- n8n versions prior to 2.5.2
- n8n workflow automation platform
- Status: Active / Patches available (1.123.17+, 2.5.2+)

## Technical Details

The vulnerability exists in n8n's workflow expression evaluation system:

### Root Cause
- n8n supports dynamic expressions inside workflows for flexible automation
- These expressions are evaluated at runtime using a JavaScript execution context
- Improper runtime validation allows specially crafted expressions to:
    - Bypass sandbox restrictions
    - Access Node.js internals
    - Invoke OS-level command execution
- TypeScript compile-time safety does not protect against runtime payload manipulation

### Attack Vector
- Specially crafted expression payloads escape the sandbox
- Direct access to Node.js `require()` and similar APIs
- Ability to invoke system commands through child_process module
- Public webhooks enable remote triggering of malicious workflows

### Exploitation Requirements
- Access to an n8n account with workflow creation/editing rights
- Ability to deploy a malicious workflow or modify existing ones
- Trigger mechanism (manual, scheduled, or webhook-based)

![alt text](images/n8n1.png)

![alt text](images/n8n2.png)

## Attack Scenario
1. Attacker gains access to an n8n account with workflow creation rights (or compromises a low-privileged user)
2. A malicious workflow is created containing a crafted expression payload that escapes the sandbox
3. The workflow is triggered manually, on schedule, or through a public webhook
4. The payload breaks out of the JavaScript sandbox and accesses Node.js internals
5. Attacker executes arbitrary system commands with the privileges of the n8n process
6. Attacker gains control over the n8n host, connected infrastructure, and stored credentials

## Impact Assessment

=== "Confidentiality"
    * Theft of API tokens and OAuth secrets stored in n8n
    * Exposure of database credentials and connection strings
    * Access to all connected system credentials and configurations
    * Data exfiltration from connected cloud services and internal APIs

=== "Integrity"
    * Full compromise of the n8n server
    * Modification of workflows enabling persistent backdoors
    * Tampering with automation processes and business logic
    * Potential supply-chain impact if n8n orchestrates downstream automation

=== "Availability"
    * Complete control over the n8n host
    * Lateral movement to connected systems and infrastructure
    * Establishment of persistence through cron jobs and backdoors
    * Disruption of critical automation workflows

## Mitigation Strategies

### Immediate Actions
- Upgrade immediately to patched versions:
    - n8n ≥ 1.123.17
    - n8n ≥ 2.5.2
- Audit all workflows for suspicious expression code and payloads
- Disable public webhooks on all non-essential workflows
- Review and revoke API tokens and OAuth credentials used by n8n

### Short-term Measures
- Restrict workflow creation and editing to trusted administrators only
- Disable or enforce authentication on all public webhook endpoints
- Run n8n with:
    - Least-privilege OS user (non-root)
    - Container isolation with restricted capabilities
    - Read-only filesystem where possible
- Implement strict access controls on workflow management
- Remove or rotate all stored credentials

### Monitoring & Detection
- Monitor workflow creation and modification activities
- Alert on suspicious JavaScript code patterns in expressions
- Track command execution attempts from n8n processes
- Monitor outbound connections from n8n to unexpected destinations
- Alert on creation of new cron jobs or scheduled tasks by n8n
- Review logs for OS-level command execution from n8n

### Long-term Solutions
- Implement network segmentation for automation platforms
- Isolate n8n in a dedicated security zone with limited connectivity
- Use secrets management solutions instead of storing credentials in workflows
- Establish continuous monitoring for workflow changes
- Deploy application-level detection for expression injection attempts
- Implement zero-trust architecture for connected systems
- Maintain vulnerability management program for all components

## Resources and References

!!! info "Incident Reports"
    - [Critical n8n Flaw CVE-2026-25049 Enables System Command Execution via Malicious Workflows](https://thehackernews.com/2026/02/critical-n8n-flaw-cve-2026-25049.html)
    - [Critical n8n flaws disclosed along with public exploits](https://www.bleepingcomputer.com/news/security/critical-n8n-flaws-disclosed-along-with-public-exploits/)
    - [A Deep Dive into CVE-2026-25049: n8n Remote Code Execution](https://blog.securelayer7.net/cve-2026-25049/)
