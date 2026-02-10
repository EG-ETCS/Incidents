## Lynx+ Gateway Critical Vulnerabilities
![Lynx+ gateway](images/lynx.png)

**Unauthorized Access & Info Disclosure**{.cve-chip}  
**CVSS 9.2 Critical**{.cve-chip}  

### Overview
A critical security vulnerability in GIC Lynx+ Gateway devices allows remote attackers to gain unauthorized access, reset devices, exfiltrate sensitive information, and capture plaintext credentials. The vulnerabilities affect multiple versions (R08, V03, V05, V18).

**Technical Specifications**  

| **Attribute** | **Details** |
|---------------|-------------|
| **CVE ID** | CVE-2025-55034, CVE-2025-58083, CVE-2025-59780, CVE-2025-62765 |
| **Vulnerability Type** | Weak Password Requirements, Missing Authentication, Information Disclosure, Cleartext Transmission |
| **Attack Vector** | Network, Remote/Passive, Over IP |
| **Authentication** | None required (multiple scenarios) |
| **Complexity** | Low |
| **User Interaction** | Not required |
| **Affected Component** | Lynx+ Gateway R08, V03, V05, V18 |

### Technical Specifications

- Weak password requirements allow brute-force login (CVE-2025-55034)
- No authentication required for remote device reset (CVE-2025-58083)
- No authentication for device information disclosure endpoints (CVE-2025-59780)
- Credentials transferred in cleartext (CVE-2025-62765)

###  Affected Products

- Lynx+ Gateway R08
- Lynx+ Gateway V03
- Lynx+ Gateway V05
- Lynx+ Gateway V18

### Attack Scenario

1. Attacker connects to the same network as the Lynx+ device
2. Exploits weak password requirements to brute-force login
3. Remotely resets the device without authentication, causing denial-of-service
4. Retrieves sensitive device information via unauthenticated HTTP GET requests
5. Sniffs network traffic to capture credentials sent in cleartext
6. Gains further access and potentially pivots into wider OT network

### Impact Assessment

- **Integrity:** Full compromise of device configuration and operational logic
- **Confidentiality:** Exposure of sensitive device information and credentials
- **Availability:** Device/service disruption through remote reset (DoS)
- **Network Security:** Entry point for deeper OT network attacks, lateral movement, and critical infrastructure exposure

### Mitigation Strategies

- **Network Isolation:** Never expose devices to the internet; place behind firewalls with strict rules
- **Access Controls:** Limit remote access to VPN-authenticated connections; segment OT from corporate IT
- **Password Policy:** Enforce strong passwords externally; monitor authentication logs
- **Encryption:** Encrypt all device communications where possible
- **Monitoring:** Deploy network monitoring for device access; alert on suspicious activity
- **Updates:** Track vendor updates/patches; apply firmware updates promptly
- **Asset Inventory:** Identify all affected devices in the environment
- **Incident Response:** Prepare procedures for potential compromise

### Technical Recommendations

1. **Immediate Actions:**  
      - Restrict internet-facing access to control systems.
      - Deploy firewalls between operational and other network segments.
      - Utilize VPN solutions for any remote access.
      - Document all devices and their network configurations.
      - Monitor network activity for unauthorized access attempts.
      - Establish incident response plans and procedures.
      - Contact vendors directly for updates and patches if available.

2. **Short-term Measures:**  
      - Implement network segmentation to keep operational technology and corporate networks separate.
      - Conduct thorough impact assessments before applying mitigation measures.
      - Regularly audit and update firewall rules and vulnerability assessments.

3. **Long-term Strategy:**  
      - Plan for replacing unsupported or end-of-life devices, engaging with vendors for migration assistance.
      - As of the advisory release, no public exploitation has been reported, but maintain vigilance for emerging threats.

### Resources and References

!!! info "Official Sources"
      - [Critical Lynx+ Gateway Vulnerability Exposes Data in Cleartext, CISA Warns](https://cyberpress.org/critical-lynx-gateway-vulnerability/)
      - [General Industrial Controls Lynx+ Gateway | CISA](https://www.cisa.gov/news-events/ics-advisories/icsa-25-317-08)
      - [NVD - CVE-2025-58083](https://nvd.nist.gov/vuln/detail/CVE-2025-58083)
      - [NVD - CVE-2025-55034](https://nvd.nist.gov/vuln/detail/CVE-2025-55034)
