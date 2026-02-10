# Oracle EBS Zero-Day Exploitation – CVE-2025-61882
![Oracle EBS](images/oracle-ebs.png)

**CVE-2025-61882**{.cve-chip}  
**Remote Code Execution**{.cve-chip}  
**Unauthenticated Network Access**{.cve-chip}

## Overview
The vulnerability resides in the Oracle Concurrent Processing component (BI Publisher Integration) of Oracle E-Business Suite (EBS). It allows an attacker with network access (no credentials, no user interaction) to execute arbitrary code on the system. The flaw is being **actively exploited in the wild** by threat actors (including those using the **Cl0p brand**) in extortion and data-theft campaigns.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **CVE ID** | CVE-2025-61882 |
| **Vulnerability Type** | Remote Code Execution via XSLT Injection |
| **Attack Vector** | Network (HTTP/HTTPS) |
| **Authentication** | None required |
| **Complexity** | Low |
| **User Interaction** | None required |
| **Affected Component** | Oracle Concurrent Processing (BI Publisher Integration) |

### Affected Versions
- Oracle EBS 12.2.3 through 12.2.14

### Mechanism
- The flaw involves injection of malicious XSLT templates (or similar) into the BI Publisher / XDO template subsystem.
- Executed via a vulnerable endpoint (e.g., `SyncServlet`/`UiServlet`) allowing Java code execution.

### Indicators of Compromise (IOCs)
Oracle advisory lists specific IPs and file hashes:

**IPs:**
- `200.107.207.26`
- `185.181.60.11`

**File Hashes:**
- `76b6d36e04e367a2334c445b51e1ecce97e4c614e88dfb4f72b104ca0f31235d`
- `aa0d3859d6633b62bccfb69017d33a8979a3be1f3f0a5a4bf6960d6c73d41121`

## Attack Scenario
1. Attacker scans internet-facing Oracle EBS installations (versions 12.2.3-12.2.14) for the vulnerable endpoint.
2. Sends a crafted HTTP request containing malicious XSL (or reference to malicious XSL hosted remotely) to the `SyncServlet`/`UiServlet` endpoint.
3. The system processes the malicious template (via XSLT engine, Java code execution) resulting in the attacker gaining arbitrary code execution on the EBS server.
4. The attacker:
   - Installs backdoors/loads additional payloads
   - Moves laterally
   - Exfiltrates data (e.g., via database tables `XDO_TEMPLATES_B`, `XDO_LOBS`)
   - Threatens victims via extortion emails (e.g., from domain `support@pubstorm.com` / `pubstorm.net`) asserting a breach
5. Victim receives extortion demand under **Cl0p brand**; attackers may post data unless paid.
6. Because proof-of-concept exploit code has leaked, risk of mass exploitation increases.

## Impact Assessment

=== "Confidentiality"
    * Full compromise of the EBS server
    * Data exfiltration of sensitive business information, possibly financial, supply chain, customer data

=== "Integrity"
    * Arbitrary code execution
    * Installation of backdoors and malicious payloads
    * Modification of system configurations

=== "Availability"
    * Potential disruption of EBS services
    * System compromise leading to operational downtime

=== "Enterprise Impact"
    * **Extortion**: Attackers threaten publication of stolen material or further disruption
    * Potential for widespread internal compromise given the central role of EBS in enterprise systems
    * High reputational, regulatory and financial risk to affected organisations
    * Because the flaw was exploited in the wild, many organisations may already be breached before patching

## Mitigations

### 🔄 Immediate Actions
- Apply **Oracle's emergency Security Alert patches** immediately for CVE-2025-61882
- **Prerequisite**: October 2023 Critical Patch Update must be installed

### 🛡️ If Immediate Patching Not Possible
- Isolate EBS servers from the internet
- Restrict access to trusted networks
- Apply network segmentation
- Block unnecessary outbound connections from EBS servers

### 🔍 Threat Hunting for IOCs
Check for:
- Oracle-specified IPs: `200.107.207.26`, `185.181.60.11`
- File hashes: `76b6d36e04e367a2334c445b51e1ecce97e4c614e88dfb4f72b104ca0f31235d`, `aa0d3859d6633b62bccfb69017d33a8979a3be1f3f0a5a4bf6960d6c73d41121`
- Database tables `XDO_TEMPLATES_B`, `XDO_LOBS` for suspicious entries

### 📊 Monitoring
Monitor for:
- Anomalous traffic, especially to remote C2 servers
- Unexpected outbound connections
- Unusual template creation in EBS modules

### 🔒 Hardening
- Apply least-privilege principles
- Enable multi-factor authentication for admin access
- Keep system up to date

### 🕵️ Post-Patch Investigation
- Assume potential compromise
- Run forensic investigation
- Restore from clean backup if needed

## Resources & References

!!! info "Official & Advisory Resources"
    * [Cl0p Zero-Day Hits Oracle E-Business Suite (CVE-2025-61882)](https://meterpreter.org/cl0p-zero-day-hits-oracle-e-business-suite-cve-2025-61882-compromising-global-giants/)
    * [NVD - CVE-2025-61882](https://nvd.nist.gov/vuln/detail/CVE-2025-61882)
    * [Oracle Security Alerts CVE-2025-61882](https://www.oracle.com/security-alerts/alert-cve-2025-61882.html)