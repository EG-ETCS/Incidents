# **Critical IBM AIX NIM Vulnerabilities (CVE-2025-36250, CVSS 10.0)**

**CVE-2025-36250**{.cve-chip}
**Remote Code Execution**{.cve-chip}
**Private Key Exposure**{.cve-chip}
**Directory Traversal**{.cve-chip}

## Overview

Multiple critical vulnerabilities in IBM AIX and VIOS systems—specifically within the NIM (Network Installation Manager) ecosystem—allow remote attackers to execute arbitrary commands, steal cryptographic private keys, or write arbitrary files via directory traversal.
The most severe vulnerability (**CVE-2025-36250**) is rated **CVSS 10.0**, enabling full remote command execution on NIM servers.

## Technical Specifications

| **Attribute**           | **Details**                                                    |
| ----------------------- | -------------------------------------------------------------- |
| **CVE IDs**             | CVE-2025-36250, CVE-2025-36251, CVE-2025-36096, CVE-2025-36236 |
| **Vulnerability Types** | RCE, Key Exposure, Directory Traversal                         |
| **Attack Vector**       | Network (remote)                                               |
| **Authentication**      | Varies (several flaws exploitable without auth)                |
| **Complexity**          | Low                                                            |
| **User Interaction**    | Not required                                                   |
| **Affected Components** | nimsh, nimesis, NIM key storage                                |

## Affected Products

* **AIX 7.2** (multiple TL/SP levels)
* **AIX 7.3**
* **VIOS 3.1**
* **VIOS 4.1**
* Affected NIM-related filesets:

  * `bos.sysmgt.nim.client`
  * `bos.sysmgt.nim.master`
  * `bos.sysmgt.sysbr`

## Attack Scenarios

### 1. Remote Command Execution (nimesis / nimsh)

* Attacker sends crafted packets to exposed `nimsh` or `nimesis` services.
* Exploits insecure process controls in SSL/TLS handling.
* Results in **unauthenticated remote code execution** (root).

### 2. NIM Private Key Theft

* AIX stores **NIM private keys insecurely**.
* MITM attacker can intercept or extract keys.
* Enables impersonation of hosts, malicious OS deployments, and long-term persistence.

### 3. Directory Traversal (Arbitrary File Write)

* Specially crafted URL allows **writing arbitrary files**.
* Can plant backdoors, replace system binaries, or alter configuration.

## Impact Assessment

=== "Integrity"

* Unauthorized OS provisioning
* Malicious modification of system files
* Backdoor insertion
* Tampering with AIX/VIOS infrastructure

=== "Confidentiality"

* Theft of NIM private keys
* Exposure of deployment architecture
* Credential compromise
* Ability to impersonate legitimate nodes

=== "Availability"

* Remote service disruption
* Possible destruction of NIM repository
* System instability or forced reinstallation
* Denial of service via malformed network packets

=== "Network Security"

* Lateral movement into management networks
* Compromise of VIOS / SAN pathways
* Root-level access to AIX systems
* Full takeover of provisioning and deployment workflows

## Mitigation Strategies

### :material-security-update: Apply IBM Patches

* Install all APARs released for:

  * AIX 7.2 / 7.3
  * VIOS 3.1 / 4.1
* This is the **only** complete fix.

### :material-network-off: Network Hardening

* Restrict access to NIM services using ACLs/firewalls
* Segregate NIM and management networks
* Block external access to `nimsh` / `nimesis` ports
* Avoid exposing AIX NIM services across untrusted networks

### :material-key-alert: Credential & Key Protection

* Rotate NIM private keys after patching
* Enforce strict TLS configurations
* Monitor for unauthorized certificate use

### :material-monitor-dashboard: Monitoring & Detection

* Deploy IDS/IPS signatures for NIM protocol anomalies
* Alert on suspicious nimsh traffic
* Log and audit provisioning operations
* Detect unexpected file writes or package deployments

### :material-update: Long-term Strategy

* Strengthen AIX management architecture
* Ensure NIM servers remain isolated
* Conduct periodic credential audits
* Train sysadmins on NIM-related security risks

## Technical Recommendations

### Immediate Actions

1. Patch all vulnerable AIX/VIOS systems
2. Rotate NIM private keys
3. Isolate the NIM server from non-admin networks
4. Block unnecessary network exposure
5. Conduct compromise assessment

### Short-term Measures

1. Implement firewall rules and VLAN segmentation
2. Enable enhanced auditing for NIM operations
3. Monitor TLS handshake anomalies
4. Review deployment logs for tampered LPAR images

### Long-term Strategy

1. Harden management networks
2. Standardize NIM security procedures
3. Replace outdated VIOS/AIX TL levels
4. Train teams on secure provisioning practices

## Resources and References

!!! info "Official Documentation"

    * [Critical IBM AIX RCE (CVE-2025-36250, CVSS 10.0) Flaw Exposes NIM Private Keys and Risks Directory Traversal](https://securityonline.info/critical-ibm-aix-rce-cve-2025-36250-cvss-10-0-flaw-exposes-nim-private-keys-and-risks-directory-traversal/)
    * [Security Bulletin: AIX is vulnerable to arbitrary command execution, insufficiently protected credentials, and path traversal](https://www.ibm.com/support/pages/node/7251173)
    * [NVD- CVE-2025-36250](https://nvd.nist.gov/vuln/detail/CVE-2025-36250)
    * [NVD- CVE-2025-36251](https://nvd.nist.gov/vuln/detail/CVE-2025-36251)

!!! danger "Critical Warning"
    These vulnerabilities include a **CVSS 10.0 RCE**.
    If NIM services are exposed on the network without patching, attackers can gain **full remote root access**.

!!! tip "Emergency Response"
    If exploitation is suspected:

    1. Isolate the NIM server immediately
    2. Rotate all NIM private keys
    3. Inspect deployment logs and file integrity
    4. Reinstall or verify LPAR images
    5. Apply APARs before reconnecting