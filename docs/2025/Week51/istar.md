# Johnson Controls iSTAR Ultra Vulnerabilities

**OS Command Injection**{.cve-chip}
**Firmware Authentication Bypass**{.cve-chip}
**Default Credentials**{.cve-chip}

## Overview
Multiple high-severity security vulnerabilities have been identified in Johnson Controls iSTAR Ultra series door controller devices, including iSTAR Ultra, iSTAR Ultra SE, iSTAR Ultra G2, iSTAR Ultra G2 SE, and iSTAR Edge G2 models. These flaws could allow attackers to modify firmware, gain elevated privileges, or access protected portions of the device, undermining access control integrity. Successful exploitation could result in unauthorized access to physical security systems, device takeover, and potential lateral movement within facility networks.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Vendor** | Johnson Controls |
| **Products** | iSTAR Ultra, iSTAR Ultra SE, iSTAR Ultra G2, iSTAR Ultra G2 SE, iSTAR Edge G2 |
| **Vulnerability Types** | OS Command Injection (CWE-78), Insufficient Verification of Firmware Authenticity (CWE-345), Default Credentials (CWE-1392) |
| **Attack Vector** | Network / Physical (depending on vulnerability) |
| **Authentication** | May be bypassed via default credentials |
| **Complexity** | Low |
| **User Interaction** | Not required |
| **CVSS v4 Score** | 8.7 (High) |

## Affected Products
- **Firmware Versions**: Versions prior to **6.9.3** are affected
- **Status**: Patches available in firmware 6.9.3 and later

## Vulnerability Details

### OS Command Injection (CWE-78)
Improper input sanitization in the device's web interface allows privileged command execution. Attackers can inject malicious commands through input fields.

### Insufficient Verification of Firmware Authenticity (CWE-345)
Weak verification mechanisms at boot time could allow tampered or malicious firmware to execute on the device, bypassing security controls.

### Default Credentials / Weak Authentication (CWE-1392)
Default "root" credentials may be present in some versions, allowing attackers to gain immediate administrative access without authentication challenges.

### Physical Interface Weaknesses
Certain vulnerabilities allow attackers with physical access via serial or USB console to access protected interfaces and sensitive system functions.

### Insecure Storage of Sensitive Information
Protected data such as credentials and configuration may be exposed due to insecure storage mechanisms on the device.

## Attack Scenario
1. **Reconnaissance**: Attacker identifies iSTAR Ultra controllers connected to a building access network through network scanning
2. **Network Access**: Attacker gains network connectivity to the device via exposed web interface or compromised local LAN
3. **Exploit Web Interface**: Attacker uses OS command injection flaw to execute unauthorized commands at elevated privilege
4. **Privilege Escalation**: Using default credentials or injection results, attacker obtains root-level access on the device firmware
5. **Firmware/Control Manipulation**: Attacker modifies firmware or configuration to weaken access control enforcement or establish persistent access

### Potential Access Points
- Exposed web management interface on building networks
- Compromised local area network segments
- Physical access to device serial or USB console ports
- Default credential exploitation via remote or local access

## Impact Assessment

=== "Integrity"
    * Unauthorized modification of access control configurations
    * Firmware manipulation and tampering
    * Alteration of door access permissions
    * Compromise of physical security enforcement

=== "Confidentiality"
    * Exposure of sensitive configuration data
    * Access to credential and authentication information
    * Visibility into physical access patterns and logs
    * Potential exposure of facility security architecture

=== "Availability"
    * Disruption of door control systems
    * Denial of physical access for legitimate users
    * System lockout or malfunction
    * Service interruption for access control

=== "Physical Security Impact"
    * **Unauthorized Access**: Unauthorized unlock or reconfiguration of access control points
    * **Device Takeover**: Full control over door controllers and physical security systems
    * **Lateral Movement**: Use compromised devices to pivot deeper into facility networks
    * **Facility Compromise**: Breach of physical security perimeter and access zones

## Mitigation Strategies

### 🔄 Immediate Actions
- **Firmware Updates**: Update affected iSTAR Ultra devices to firmware version **6.9.3 or later** immediately
- **Credential Reset**: Replace all default credentials with strong, unique passwords
- **Access Audit**: Review and audit all administrative access to door controllers
- **Network Assessment**: Identify all exposed iSTAR devices on the network

### 🛡️ Strong Authentication
- Replace default "root" credentials with complex, unique passwords
- Implement multi-factor authentication where supported
- Use strong password policies (minimum length, complexity requirements)
- Regularly rotate administrative credentials
- Maintain separate credentials for each device

### 📊 Network Segmentation
- Isolate access control devices from broader enterprise networks
- Implement VLAN segmentation for physical security systems
- Restrict administrative access to dedicated management networks
- Apply firewall rules to limit access to controller interfaces
- Use jump hosts or bastion servers for administrative access

### 🔒 Physical Security
- Limit physical access to controller hardware
- Install devices in secured enclosures with tamper protection
- Implement tamper-evident seals on device housings
- Monitor and log physical access to controller locations
- Restrict USB and serial console port access

### 🔍 Monitoring & Detection
- Monitor for unusual access attempts to controller web interfaces
- Alert on configuration changes or firmware updates
- Log all administrative actions and access control modifications
- Deploy intrusion detection systems for physical security networks
- Review logs regularly for suspicious command execution patterns
- Monitor for use of default credentials or brute-force attempts

## Resources and References

!!! info "Official Documentation"
    - [Johnson Controls iSTAR Ultra | CISA](https://www.cisa.gov/news-events/ics-advisories/icsa-25-345-02)
    - [Johnson Controls iSTAR Ultra, iSTAR Ultra SE, iSTAR Ultra G2, iSTAR Ultra G2 SE, iSTAR Edge G2 - Tisalabs Advisory](https://www.tisalabs.com/advisories/johnson-controls-istar-ultra-istar-ultra-se-istar-ultra-g2-istar-ultra-g2-se-istar-edge-g2/)

!!! danger "Critical Warning"
    These vulnerabilities affect physical security systems controlling building access. Immediate firmware updates and credential changes are essential to prevent unauthorized physical access and facility compromise.