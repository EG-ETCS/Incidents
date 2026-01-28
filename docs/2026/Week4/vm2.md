# vm2 Sandbox Escape Vulnerability

**CVE-2026-22709**{.cve-chip}  **Sandbox Escape**{.cve-chip}  **Arbitrary Code Execution**{.cve-chip}

## Overview
CVE-2026-22709 is a critical sandbox escape vulnerability in vm2, a popular Node.js library used to execute JavaScript code in isolated contexts. The flaw stems from incomplete sanitization of Promise callbacks, allowing attackers to bypass sandbox restrictions and execute arbitrary code on the host system with full Node.js process privileges. This vulnerability affects any environment that runs untrusted code via vm2, including CI/CD pipelines, code execution services, plugin systems, and developer tooling.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **CVE ID** | CVE-2026-22709 |
| **Vulnerability Type** | Sandbox Escape via Promise Callback Bypass |
| **CVSS Score**| 9.8 (Critical) |
| **Attack Vector** | Local (requires untrusted code execution) |
| **Authentication** | None |
| **Complexity** | Medium |
| **User Interaction** | Not Required |
| **Affected Component** | vm2 Node.js sandbox library |

## Affected Products
- vm2 versions prior to 3.10.2
- Applications using vm2 for untrusted code execution
- CI/CD pipelines with code execution stages
- Code playground and REPL services
- Plugin systems and developer tooling
- Status: Active / Patch available (version 3.10.2+)

## Technical Details

The vulnerability arises from incomplete sanitization of Promise callbacks in vm2's isolation mechanism:

- **Root cause**: `localPromise.prototype.then` is properly sanitized, but `globalPromise.prototype.then` and `catch` are not
- **Exploitation vector**: Async functions return `globalPromise` objects which bypass the intended sanitization
- **Escape mechanism**: Attackers leverage unsanitized callbacks to access native constructors (e.g., `Function`)
- **Privilege escalation**: With access to native constructors, attackers can call modules like `child_process` to execute arbitrary code outside the sandbox

The flaw allows code intended to run in isolation to execute with the full privileges of the host Node.js process, completely undermining the security boundary that vm2 is designed to provide.

## Attack Scenario
1. Attacker submits or injects malicious JavaScript into an application that uses vm2 to run untrusted code
2. The malicious code uses async/Promise patterns to obtain a `globalPromise` object
3. The attacker attaches malicious callbacks to `.then()` or `.catch()` methods which vm2 fails to sanitize
4. Through the unsanitized callback, the attacker accesses native constructors and host resources
5. Arbitrary code execution is achieved on the host system, allowing execution of shell commands, file system access, or network operations with full Node.js process privileges

## Impact Assessment

=== "Confidentiality"
    * Complete access to host filesystem and sensitive data
    * Theft of environment variables, secrets, and credentials
    * Extraction of source code and intellectual property
    * Access to database credentials and API keys

=== "Integrity"
    * Arbitrary code execution with full process privileges
    * Modification of application code and data
    * Injection of malicious payloads into CI/CD pipelines
    * Tampering with build artifacts and deployment packages

=== "Availability"
    * Denial of service through resource exhaustion
    * Disruption of critical services and workflows
    * Potential ransomware deployment
    * System compromise affecting service continuity

## Mitigation Strategies

### Immediate Actions
- Upgrade vm2 to version 3.10.2 or later immediately
- Audit codebases to identify all vm2 usages using `npm audit`, dependency scanners, or Snyk
- Review recent logs for suspicious activity from sandboxed code execution
- Isolate affected components in hardened containers or VMs until patched

### Short-term Measures
- Restrict execution contexts and avoid executing untrusted code until patched
- Implement additional input validation and sanitization before code execution
- Deploy runtime application self-protection (RASP) to monitor sandbox behavior
- Use containerization with limited capabilities for vm2 workloads
- Monitor logs for unusual executions from sandboxed code (e.g., unexpected system calls)

### Monitoring & Detection
- Track spawning of child processes from Node.js applications using vm2
- Monitor for suspicious module imports (child_process, fs, net)
- Alert on unexpected file system or network access from sandboxed environments
- Log all code execution attempts and review for anomalies
- Detect use of eval(), Function(), or other code generation patterns
- Monitor for access to sensitive APIs from sandbox contexts

### Long-term Solutions
- Consider sandbox alternatives with stronger isolation guarantees (e.g., isolated-vm, VM2 alternatives)
- Run untrusted code in separate processes or virtual machines with restricted permissions
- Implement defense-in-depth with multiple layers of isolation
- Use WebAssembly-based sandboxing solutions for stronger isolation
- Adopt least-privilege principles for Node.js process execution
- Establish continuous vulnerability monitoring for all dependencies
- Implement secure code review processes for sandbox usage patterns

## Resources and References

!!! info "Incident Reports"
    - [Critical sandbox escape flaw found in popular vm2 NodeJS library](https://www.bleepingcomputer.com/news/security/critical-sandbox-escape-flaw-discovered-in-popular-vm2-nodejs-library/)
    - [vm2 has a Sandbox Escape | GitLab Advisory Database](https://advisories.gitlab.com/pkg/npm/vm2/CVE-2026-22709/)
    - [NVD - CVE-2026-22709](https://nvd.nist.gov/vuln/detail/CVE-2026-22709)
    - [vm2 Sandbox Escape via Promise Callback Bypass (CVE-2026-22709) – TheHackerWire](https://www.thehackerwire.com/vm2-sandbox-escape-via-promise-callback-bypass-cve-2026-22709/)
    - [Critical vm2 Sandbox Vulnerability in Node.js Lets Attackers Run Untrusted Code](https://cyberpress.org/critical-vm2-sandbox-vulnerability-in-node-js-lets-attackers-run-untrusted-code/)
    - [Critical vm2 Flaw Lets Attackers Bypass Sandbox and Execute Arbitrary Code in Node.js](https://gbhackers.com/critical-vm2-flaw-arbitrary-code-in-node-js/)
