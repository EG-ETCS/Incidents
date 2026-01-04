# ABB FLXeon Controllers Vulnerabilities

**CVE-2024-48842** {.cve-chip}
**CVE-2024-48851** {.cve-chip}
**CVE-2025-10205** {.cve-chip}
**CVE-2025-10207** {.cve-chip}

## Overview
Multiple high-severity vulnerabilities have been identified in ABB’s FLXeon series controllers, including models FBXi, FBVi, FBTi, and CBXi running firmware version 9.3.5 and earlier.  
These flaws include hard-coded credentials, improper input validation that allows remote code execution, weak MD5-based password storage, and unsafe file path handling.  
Successful exploitation could allow remote attackers to gain full control of affected devices, execute arbitrary code, and potentially disrupt industrial operations or building management systems.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Vendor** | ABB |
| **Products** | FBXi, FBVi, FBTi, CBXi Controllers |
| **Firmware Versions** | ≤ 9.3.5 |
| **Vulnerability Types** | Hard-Coded Credentials (CWE-798), Improper Input Validation (CWE-1287), Weak One-Way Hash (CWE-759) |
| **Attack Vector** | Network / Local depending on configuration |
| **Authentication** | May be bypassed due to fixed credentials |
| **Complexity** | Low |
| **User Interaction** | Not required |
| **CVSS v4 Score** | 8.7 (High) |

## Affected Products
- **FBXi-8R8-X96 (2CQG201028R1011)**
- **FBXi-8R8-H-X96 (2CQG201029R1011)**
- **FBXi-X256 (2CQG201014R1021)**
- **FBXi-X48 (2CQG201018R1021)**
- **FBVi-2U4-4T (2CQG201015R1021)**
- **FBTi-6T1-1U1R (2CQG201022R1011)**
- **CBXi-8R8 (2CQG201001R1021)**  
_All devices running firmware version 9.3.5 or prior are affected._

## Vulnerability Details

- **CVE-2024-48842 – Hard-Coded Credentials**
The controller uses fixed, built-in login credentials that cannot be securely stored or modified. Attackers with knowledge of these credentials can gain full system access.

- **CVE-2024-48851 – Improper Input Validation (Remote Code Execution)**
Insufficient input validation allows remote attackers to send specially crafted data that can lead to arbitrary code execution on the controller.

- **CVE-2025-10205 – Weak Password Hashing**
User passwords are protected using the insecure MD5 algorithm with low entropy salts, and stored in plaintext on unencrypted partitions. This makes it easy for attackers to crack passwords.

- **CVE-2025-10207 – Improper Input Validation (File Path Manipulation)**
Users can upload files into restricted directories, allowing the overwriting of critical system files and possible command execution.

## Attack Scenario
1. The attacker identifies a vulnerable FLXeon controller exposed to the Internet or accessible via an internal network.  
2. Using hard-coded credentials or cracked MD5 hashes, the attacker gains access.  
3. Malicious files or commands are uploaded through improper validation flaws.  
4. Remote code execution or file manipulation enables full control of the device.  
5. The attacker disrupts operations or moves laterally within the ICS environment.

### Potential Access Points
- Direct Internet exposure or NAT-forwarded interfaces  
- Remote management portals  
- Internal OT networks lacking segmentation  
- Compromised VPN access or shared credentials

## Impact Assessment

=== "Integrity"
    * Unauthorized modification of firmware and configuration files  
    * Manipulation of control logic and operational parameters  
    * Tampering with industrial automation settings  

=== "Confidentiality"
    * Exposure of stored credentials and sensitive configuration data  
    * Leakage of device and network information  
    * Potential visibility into connected industrial networks  

=== "Availability"
    * Device crashes and operational disruption  
    * Denial of service in control or monitoring systems  
    * Shutdown of connected processes or subsystems  

=== "Operational Risk"
    * Full device compromise  
    * Disruption of industrial and building management processes  
    * Safety and compliance violations  

## Mitigation Strategies

### :material-network-off: Network Protection
- **Disconnect** any FLXeon devices directly exposed to the Internet.  
- **Segment** control networks from corporate or public networks.  
- **Use firewalls** to restrict network access to trusted IP ranges only.  
- **Disable unused services** and management interfaces.

### :material-security-network: Access Controls
- **Update firmware** to the latest release (≥ 9.3.6) when available.  
- **Enforce VPN-only access** for remote connections with strong authentication.  
- **Apply physical access controls** to prevent unauthorized manipulation.  
- **Audit accounts and credentials** to remove defaults or shared passwords.

### :material-monitor-dashboard: Monitoring & Detection
- **Deploy intrusion detection systems (IDS/IPS)** on ICS networks.  
- **Monitor logs** for abnormal login attempts or file uploads.  
- **Alert on changes** to configuration and firmware images.  
- **Regularly review access patterns** for suspicious activity.

## Technical Recommendations

### Immediate Actions
1. **Identify** all FLXeon controllers in your environment.  
2. **Disconnect or isolate** any Internet-facing units.  
3. **Upgrade** to patched firmware as soon as available.  
4. **Change all credentials** and replace MD5-based password storage.  
5. **Restrict access** to essential users only.

### Short-term Measures
1. **Apply firewall rules** to limit inbound connections.  
2. **Enable network monitoring** for anomalous traffic.  
3. **Review device configurations** for unsafe exposure.  
4. **Back up critical configurations** before patching.

### Long-term Strategy
1. **Implement continuous vulnerability scanning** for ICS assets.  
2. **Adopt strong credential management policies.**  
3. **Regularly update security awareness** for maintenance teams.  
4. **Coordinate with ABB** for firmware roadmap and support lifecycle.

## Resources and References

!!! info "Official Documentation"
    - [CISA Advisory – ICSA-25-310-03: ABB FLXeon Controllers](https://www.cisa.gov/news-events/ics-advisories/icsa-25-310-03)
    - [ABB Cybersecurity Advisory – 9AKK108471A7121 (PDF)](https://library.e.abb.com/public/422d6569e50740ec924cd7aedec30eae/9AKK108471A7121_en_pdf_C_ABBVREP0213%20Advisory%20FLXeon%20Controllers.pdf)
    - [NVD - CVE-2025-10205](https://nvd.nist.gov/vuln/detail/CVE-2025-10205)

!!! danger "Critical Warning"
    Some vulnerabilities (hard-coded credentials, weak password hashing) have no permanent fix at this time. Isolation and access control are essential until firmware patches are released.

!!! tip "Emergency Response"
    1. Immediately isolate any potentially compromised controller.  
    2. Review device and network logs for suspicious actions.  
    3. Replace or rotate all credentials.  
    4. Restore configurations from known-good backups.  
    5. Report any incidents to ABB and CISA.
