# ArrayOS AG VPN (CVE-2025-66644)
![ArrayOS AG VPN](images/arrayos.png)

**Command Injection**{.cve-chip}  
**VPN Gateway Compromise**{.cve-chip}  
**Active Exploitation**{.cve-chip}

## Overview

A **command-injection flaw** in ArrayOS AG (versions prior to 9.4.5.9), specifically affecting the **"DesktopDirect"** remote-desktop/remote-access feature. Remotely authenticated (or under some conditions "network reachable") attackers can submit crafted input that gets passed unsafely to OS commands — leading to **arbitrary command execution** on the gateway.

Attackers have been observed dropping **webshells** (e.g., PHP-based) under directories like `/ca/aproxy/webapp/` on compromised VPN gateways and creating **unauthorized user accounts** to establish persistent access.

## Technical Specifications

| **Attribute**         | **Details**                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| **CVE ID**            | CVE-2025-66644                                                              |
| **Vulnerability Type**| OS Command Injection (CWE-78)                                               |
| **Affected Product**  | Array Networks ArrayOS AG                                                   |
| **Affected Versions** | Before 9.4.5.9                                                              |
| **Affected Feature**  | DesktopDirect (remote-desktop/remote-access)                                |
| **CVSS 3.1 Score**    | High (AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H)                                  |
| **Attack Vector**     | Network                                                                     |
| **Attack Complexity** | Low                                                                         |
| **Privileges Required**| High (but exploitable under some conditions)                               |
| **User Interaction**  | None                                                                        |
| **Exploitation Status**| **Active exploitation confirmed** - Added to CISA KEV                      |

## Technical Details

### Vulnerability Class
- **OS command injection (CWE-78)**
- Improper Neutralization of Special Elements used in an OS Command

### CVSS 3.1 Vector
- **AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H**
    - Network attack vector
    - Low complexity
    - Privileges required (high) but no user interaction

### Affected Versions
- ArrayOS AG **before 9.4.5.9**

### Exploitation Path
- Via **DesktopDirect** feature
- Attackers send **specially crafted requests** to web management / remote-access interfaces
- Injecting shell commands through unsanitized input

### Post-Exploitation Artifacts
- **Webshells dropped** (e.g., PHP-based) under directories like:
    - `/ca/aproxy/webapp/`
- **Unauthorized user accounts created** to establish persistent access
- Commands executed as **root or privileged user**

## Attack Scenario

1. **Target Identification**: Attacker identifies an internet-accessible/vulnerable ArrayOS AG gateway with DesktopDirect enabled (version < 9.4.5.9).

2. **Exploitation**: Attacker sends **specially crafted network request** to the gateway's DesktopDirect / remote-access interface, exploiting unsanitized input to inject OS commands.

3. **Command Execution**: Gateway executes OS commands as **root or privileged user** — attacker uses this to drop a **webshell** (e.g., PHP) under web-accessible directory (e.g., `/ca/aproxy/webapp/`).

4. **Persistence**: With webshell in place, attacker gains:
    - Remote code execution / interactive shell capability
    - Can create **unauthorized user accounts**
    - Pivot internally
    - Maintain persistence — **regardless of credential or configuration changes**

5. **Post-Exploitation**: Attacker may perform:
    - Reconnaissance
    - Lateral movement
    - Data exfiltration
    - Install additional malware
    - Depending on target environment

(This scenario matches documented incidents.)

## Impact Assessment

=== "Gateway Compromise"
    * **Full compromise** of VPN gateway / remote-access infrastructure
    * Attackers gain root/privileged access to the gateway
    * Can execute arbitrary commands

=== "Network Exposure"
    * **Exposure of internal network** behind VPN
    * Attacker may pivot to internal systems
    * Lateral movement opportunities

=== "Persistent Access"
    * **Persistent unauthorized access** via:
          - Webshells
          - Rogue accounts
    * Remains even after patch or credential change

=== "Data & Operations"
    * Potential data exfiltration
    * Privilege escalation
    * Lateral movement
    * Disruption to remote access services
    * Possibly denial-of-service or system instability

=== "Trust & Compliance"
    * Loss of trust / compliance risk for organizations relying on secure remote access
    * Breach of security perimeter

## Mitigations

### 🔄 Patch Immediately
- **Upgrade all ArrayOS AG appliances** to version **9.4.5.9 or later**
- This is the primary mitigation

### 🚫 Disable DesktopDirect
- **Disable DesktopDirect** if not required
- Removes attack vector entirely

### 🛡️ Input Validation & URL Filtering
- Implement **URL filtering / input validation**
- Block URLs containing **semicolons** (often used in command injection payloads)
- If DesktopDirect must stay enabled

### 🔒 Access Control
- **Restrict management interface access**:
    - Ensure only **trusted IPs / networks** can reach the gateway
    - Place behind VPN or firewall
    - Enforce **strong authentication (MFA)** for admin access

### 🔍 Incident Response / Detection

Conduct forensic inspection of all gateways:

#### Search for Webshells
- Check for suspicious files under:
    - `/ca/aproxy/webapp/`
    - Other web-accessible directories
- Look for PHP, JSP, or other script files

#### Account Audit
- Look for **unexpected user accounts**
- Review account creation logs
- Check for unauthorized privileged accounts

#### Log Analysis
- Review logs (pre- and post-patch)
- Monitor for suspicious outbound connections (C2)
- Check for unusual command execution patterns

#### Isolation
- **Isolate compromised devices** immediately
- Prevent further lateral movement

### 🏗️ Network Segmentation
- **Avoid exposing VPN gateway** to public internet unless strictly necessary
- **Segment remote-access infrastructure** from critical internal systems
- Apply **principle of least privilege**

### 📊 Monitoring
- Monitor for:
    - Unusual file creation in web directories
    - New user account creation
    - Anomalous outbound connections
    - Unexpected process spawning
    - Command injection patterns in logs

## Resources & References

!!! info "Official Advisories & CISA"
    * [CISA Known Exploited Vulnerabilities Catalog - CVE-2025-66644](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2025-66644)
    * [CISA Adds Two Critical KEV Vulnerabilities CVE-2022-37055 and CVE-2025-66644](https://windowsforum.com/threads/cisa-adds-two-critical-kev-vulnerabilities-cve-2022-37055-and-cve-2025-66644.392917/)
    * [Remote command execution in ArrayOS AG](https://www.cybersecurity-help.cz/vdb/SB20251208137)

!!! warning "Vulnerability Details & Analysis"
    * [CVE Record: CVE-2025-66644](https://www.cve.org/CVERecord?id=CVE-2025-66644)
    * [CVE-2025-66644: CWE-78 OS Command Injection - Threat Radar | OffSeq](https://radar.offseq.com/threat/cve-2025-66644-cwe-78-improper-neutralization-of-s-b695b96a)
    * [CISA Adds Array Networks and D-Link Vulnerabilities to KEV Catalog – TheCyberThrone](https://thecyberthrone.in/2025/12/09/cisa-adds-array-networks-and-d-link-vulnerabilities-to-kev-catalog/)

!!! danger "Active Exploitation"
    This vulnerability is being **actively exploited** in the wild and has been added to **CISA's Known Exploited Vulnerabilities (KEV) catalog**. Organizations using ArrayOS AG must **patch immediately** and conduct forensic analysis of all gateways.

!!! tip "Detection Indicators"
    **Webshell Locations to Check:**
    ```
    /ca/aproxy/webapp/
    ```
    
    **Look for:**
    
    - Unexpected PHP files
    - Recently modified files in web directories
    - Suspicious user accounts
    - Unusual outbound connections