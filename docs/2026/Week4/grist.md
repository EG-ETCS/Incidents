# Critical Grist-Core Vulnerability Allows RCE Attacks via Spreadsheet Formulas

**CVE-2026-24002**{.cve-chip}  **Remote Code Execution**{.cve-chip}  **Sandbox Escape**{.cve-chip}

## Overview
A critical vulnerability in Grist-Core's handling of Python spreadsheet formulas executed via the Pyodide WebAssembly sandbox allows attackers to achieve remote code execution. The flaw, dubbed "Cellbreak," enables specially crafted formulas to escape sandbox restrictions and run arbitrary OS commands or host JavaScript, collapsing the boundary between spreadsheet logic and server execution. This vulnerability poses a severe threat to Grist-Core deployments, potentially allowing complete server compromise through malicious spreadsheet manipulation.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **CVE ID** | CVE-2026-24002 |
| **Vulnerability Type** | Remote Code Execution (RCE) via Sandbox Escape |
| **CVSS Score**| 9.0 (Critical) |
| **Attack Vector** | Network |
| **Authentication** | Low (requires user/system to load spreadsheet) |
| **Complexity** | Medium |
| **User Interaction** | Required |
| **Affected Component** | Pyodide WebAssembly sandbox in Grist-Core |

## Affected Products
- Grist-Core versions prior to 1.7.9
- Deployments using Pyodide sandbox flavor (default configuration)
- Status: Active / Patch available (version 1.7.9+)

## Technical Details

The vulnerability stems from a Pyodide sandbox escape where the Python execution environment in WebAssembly fails to fully isolate untrusted code. The implementation relied on a blocklist-style sandbox that could be circumvented through:

- **Class hierarchy traversal**: Attackers can navigate through Python internals to access restricted objects
- **Access to dangerous modules**: Functions like `ctypes` can be reached despite sandbox restrictions
- **WebAssembly boundary violations**: Escaped code can invoke system calls or execute JavaScript in the host context

Once the sandbox is breached, malicious code gains the ability to:

- Execute arbitrary OS commands on the server host
- Run JavaScript in the host environment
- Access filesystem and network resources
- Manipulate process memory and execution flow

## Attack Scenario
1. Attacker embeds a malicious Python formula into a Grist spreadsheet document
2. The spreadsheet is shared, imported, or loaded by a user or automated system
3. Grist-Core instance with vulnerable Pyodide sandboxing processes the spreadsheet
4. The crafted formula executes and exploits class hierarchy traversal to escape the sandbox
5. With sandbox escape achieved, attacker executes arbitrary OS commands, accesses sensitive files, extracts credentials, or establishes persistence for lateral movement

## Impact Assessment

=== "Confidentiality"
    * Access to database credentials and API keys stored on the host
    * Exposure of sensitive files and configuration data
    * Potential extraction of user data from Grist databases
    * Access to environment variables containing secrets

=== "Integrity"
    * Arbitrary modification of spreadsheet data and business logic
    * Manipulation of system files and configurations
    * Code injection into application workflows
    * Backdoor installation for persistent access

=== "Availability"
    * Complete control over the vulnerable server process
    * Potential service disruption or denial-of-service
    * Resource exhaustion through malicious code execution
    * Operational disruption affecting data processing workflows

## Mitigation Strategies

### Immediate Actions
- Update Grist-Core to version 1.7.9 or later immediately
- Switch sandbox method by setting `GRIST_SANDBOX_FLAVOR=gvisor` environment variable as temporary mitigation
- Audit recent spreadsheet imports for suspicious formulas or unexpected code patterns
- Review system logs for unusual process execution or filesystem access patterns

### Short-term Measures
- Avoid unsafe configuration: Do not set `GRIST_PYODIDE_SKIP_DENO=1` which bypasses safer execution defaults
- Review and audit all user-provided spreadsheets before importing into production systems
- Restrict access and user privileges in Grist-Core deployments
- Implement strict input validation for spreadsheet formulas
- Disable formula execution for untrusted or external spreadsheets when possible

### Monitoring & Detection
- Implement logging and monitoring to detect unusual program execution patterns
- Monitor for unexpected child processes spawned by Grist-Core
- Track filesystem access attempts outside normal application directories
- Alert on network connections initiated from Grist-Core processes
- Monitor for suspicious Python module imports (ctypes, subprocess, etc.)
- Review audit logs for unauthorized data access or modification

### Long-term Solutions
- Use network segmentation and firewalls to isolate Grist-Core services from critical infrastructure
- Implement application-level sandboxing with defense-in-depth approach
- Deploy Grist-Core in containerized environments with restricted capabilities
- Establish code review processes for spreadsheet templates and formulas
- Maintain up-to-date vulnerability scanning for all deployed instances
- Consider using gVisor or similar secure sandbox implementations as default
- Implement least-privilege access controls for Grist-Core service accounts

## Resources and References

!!! info "Incident Reports"
    - [Critical Grist-Core Vulnerability Allows RCE Attacks via Spreadsheet Formulas](https://thehackernews.com/2026/01/critical-grist-core-vulnerability.html)
    - [Critical Cellbreak Vulnerability CVE-2026-24002 in Grist-Core](https://www.ctrlaltnod.com/news/critical-cellbreak-flaw-in-grist-core-allows-code-execution/)
    - [Pyodide Sandbox Escape Enables Remote Code Execution in Grist-Core - Infosecurity Magazine](https://www.infosecurity-magazine.com/news/pyodide-sandbox-escape-rce-grist/)
    - [Top 10 Daily Cybercrime Brief by FCRF [28.01.2026]: Click here to Know More - The420.in](https://the420.in/top-10-daily-cybercrime-brief-by-fcrf-click-here-to-know-more-393/)
    - [NVD - cve-2026-24002](https://nvd.nist.gov/vuln/detail/cve-2026-24002)
