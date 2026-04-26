# FIRESTARTER Backdoor on Cisco ASA / Firepower Devices
![alt text](images/FIRESTARTER.png)

**FIRESTARTER**{.cve-chip}  **Cisco ASA/FTD**{.cve-chip}  **Persistent Backdoor**{.cve-chip}  **Federal Network Impact**{.cve-chip}

## Overview
The U.S. Cybersecurity and Infrastructure Security Agency (CISA) identified a sophisticated backdoor named FIRESTARTER on a Cisco ASA firewall within a federal network. The malware enabled persistent access even after security patches were applied, allowing attackers to maintain long-term control of a critical perimeter security device.

The case highlights that patching alone may not remove advanced appliance-level persistence after compromise.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Targeted Devices** | Cisco ASA and Firepower Threat Defense (FTD) |
| **Exploited CVEs** | CVE-2025-20333 (RCE), CVE-2025-20362 (authentication bypass) |
| **Attack Method** | Crafted HTTP request exploitation; some paths may require valid VPN credentials |
| **Primary Capabilities** | Persistent backdoor, remote command execution, unauthorized firewall access |
| **Persistence Characteristic** | Survives standard patching/firmware update workflows |
| **Likely Implant Location** | System-level appliance components |

## Affected Products
- Cisco ASA perimeter firewall deployments
- Cisco Firepower Threat Defense (FTD) appliances
- Organizations with internet-facing management or VPN attack surface exposure
- Environments relying on patch-only remediation after confirmed appliance compromise

## Attack Scenario
1. **Credential Access**:
   Attacker obtains VPN credentials (phishing, credential theft, or reuse).

2. **Initial Exploitation**:
   Vulnerable Cisco ASA/FTD paths are exploited through crafted requests.

3. **Privilege Acquisition**:
   Root-level/control-plane access is achieved on the firewall.

4. **Backdoor Deployment**:
   FIRESTARTER is installed to maintain persistent unauthorized access.

5. **False Recovery Assumption**:
   Organization applies patches and considers device remediated.

6. **Re-Entry and Abuse**:
   Backdoor remains active, enabling return access without re-exploitation.

## Impact Assessment

=== "Integrity"
    * Full compromise of perimeter security policy and trust boundaries
    * Ability to alter firewall behavior, rule logic, and traffic control paths
    * Increased risk of covert long-term manipulation of network defenses

=== "Confidentiality"
    * Unauthorized monitoring/interception opportunity for transiting network traffic
    * Elevated data exfiltration risk through attacker-controlled perimeter infrastructure
    * Intelligence collection potential for follow-on intrusion stages

=== "Availability"
    * Persistent access supports repeated operational disruption and re-compromise
    * Increased blast radius for lateral movement into internal networks
    * Extended incident response and recovery time due to hidden persistence

## Mitigation Strategies

### Immediate Actions
- Perform full device reimaging/rebuild of compromised appliances, not patch-only remediation.
- Apply latest Cisco security patches after clean rebuild.
- Reset and rotate credentials, especially VPN and privileged admin credentials.

### Short-term Measures
- Conduct forensic analysis to confirm compromise scope and persistence artifacts.
- Monitor appliance logs and outbound connections for anomalies.
- Restrict management-plane access to trusted, segmented administrative networks.

### Monitoring & Detection
- Alert on suspicious configuration changes and unexpected control-plane commands.
- Track abnormal authentication behavior tied to VPN/admin accounts.
- Integrate firewall integrity monitoring into SIEM/SOC workflows.

### Long-term Solutions
- Implement zero-trust segmentation to limit perimeter-device compromise impact.
- Enforce appliance integrity verification and baseline validation processes.
- Include network-device compromise scenarios in incident response exercises.

## Resources and References

!!! info "Open-Source Reporting"
    - [CISA reports persistent FIRESTARTER backdoor on Cisco ASA device in federal network](https://securityaffairs.com/191241/hacking/cisa-reports-persistent-firestarter-backdoor-on-cisco-asa-device-in-federal-network.html)
    - [FIRESTARTER Backdoor | CISA](https://www.cisa.gov/news-events/analysis-reports/ar26-113a)
    - [FIRESTARTER Backdoor Hit Federal Cisco Firepower Device, Survives Security Patches](https://thehackernews.com/2026/04/firestarter-backdoor-hit-federal-cisco.html)
    - [US Federal Agency's Cisco Firewall Infected With 'Firestarter' Backdoor - SecurityWeek](https://www.securityweek.com/us-federal-agencys-cisco-firewall-infected-with-firestarter-backdoor/)
    - [CISA: US agency breached through Cisco vulnerability, FIRESTARTER backdoor allowed access through March | The Record from Recorded Future News](https://therecord.media/cisa-us-agency-breached-cisco-vulnerability-backdoor)
    - [CISA, NCSC issue Firestarter backdoor warning | The Register](https://www.theregister.com/2026/04/24/government_cni_on_high_alert/)

---

*Last Updated: April 26, 2026*
