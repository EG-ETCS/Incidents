# Johnson Controls FX80 / FX90 Vulnerability (CVE-2025-43867)

**Configuration File Compromise**{.cve-chip}  
**Building Automation**{.cve-chip}  
**ICS/OT Systems**{.cve-chip}

## Overview
A vulnerability in Johnson Controls FX80 and FX90 building-automation controllers (when running certain versions of their "Facility Explorer" software). Under some conditions, an attacker could compromise the device's configuration files — meaning the attacker could read/write or tamper with device configs.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **CVE ID** | CVE-2025-43867 |
| **Affected Products** | Johnson Controls FX80, FX90 building-automation controllers |
| **Affected Versions** | FX14.10.10, FX14.14.1 |
| **Vulnerability Type** | Dependency on vulnerable third-party component (CWE-1395) |
| **Attack Vector** | Network or Local |
| **Attack Complexity** | Not specified |
| **Authentication** | Required (network or local access to building-automation system) |
| **Affected Environment** | Building Automation Systems / ICS/OT |
| **Additional CVEs** | May trigger CVE-2025-3936 through CVE-2025-3945 |

## Technical Details

### Affected Versions
- **FX80** or **FX90** running:
    - **FX14.10.10**
    - **FX14.14.1**
- (These correspond to certain builds of the underlying automation platform)

### Root Cause
- Vulnerability due to **dependency on a vulnerable third-party component**
- Classified under **CWE-1395** (Dependency on Vulnerable Third-Party Component)

### Exploitation Impact
- Successful exploitation could allow **compromise (read/modify) of device configuration files**
- According to the vendor, exploitation could trigger additional CVEs:
    - **CVE-2025-3936** through **CVE-2025-3945**
- This vulnerability may serve as a **foothold for further attack vectors**

## Attack Scenario

While the vendor advisory doesn't describe a public "exploit in the wild," the general risk scenario is:

1. **Initial Access**: A malicious actor with access (network or local) to the building-automation system could exploit the vulnerability.

2. **Configuration Compromise**: Attacker gains unauthorized ability to **read or modify controller configuration files**.

3. **System Manipulation**: This could lead to:
    - Misconfiguration
    - Unauthorized control
    - Persistent compromise of the building's automation system

4. **Impact on Building Systems**: Because building-automation systems often manage:
    - HVAC
    - Climate control
    - Access control
    - Other critical building services
   
    This could result in **disruption or misuse** of those systems.

5. **Broader Infrastructure Risk**: This aligns with broader industry warnings about ICS vulnerabilities giving attackers **"latent kill switches"** over building/facility infrastructure.

## Impact Assessment

=== "Configuration Control"
    * Unauthorized modification of building-automation controller configuration
    * Control over HVAC, environmental control
    * Possibly security or access control systems

=== "Operational Impact"
    * Possible service disruptions
    * Mis-configuration
    * Loss of operational integrity of building systems

=== "Lateral Movement"
    * If controllers are networked or integrated with other systems
    * Potential lateral movement or further compromise within facility operations

=== "Critical Infrastructure Risk"
    * Risk to critical infrastructure
    * Especially in commercial buildings, industrial facilities
    * Any facility relying on building automation

!!! info "Exploitation Status"
    As of the advisory, there are **no public reports** of active exploitation / breaches leveraging this specific vulnerability.

## Mitigations

### 🔄 Upgrade Affected Systems

- **For FX80/FX90 running version 14.10.10:**
    - Update to **14.10.11**

- **For FX80/FX90 running version 14.14.1:**
    - Update to **14.14.2**

### 🛡️ Hardening & Best Practices
- Follow the vendor's **"Hardening Guide"** / cybersecurity best practices for building-automation systems:
    - Network segmentation
    - Access control
    - Limiting exposure
    - Least-privilege
    - Secure configurations

### 🌐 Network Isolation
- **Limit network exposure** of ICS devices
- Avoid exposing them to internet or untrusted networks
- **Isolate ICS/OT networks** from general enterprise/business networks

### 🔒 Access Control
- Restrict access to building-automation systems
- Implement strong authentication
- Monitor for unauthorized access attempts

### 📊 Monitoring
- Log and monitor access to building-automation controllers
- Watch for unexpected configuration changes
- Alert on anomalous behavior

## Resources & References

!!! info "Official Advisory"
    * [CISA - Johnson Controls FX Server, FX80 and FX90 (Update A)](https://www.cisa.gov/news-events/ics-advisories/icsa-25-219-02)