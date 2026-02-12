# Senegal National ID Office Ransomware Attack
![alt text](images/senegal.png)

**Ransomware**{.cve-chip}  **National ID Systems**{.cve-chip}  **Data Breach**{.cve-chip}

## Overview
Senegal's Directorate of File Automation (DAF), the agency responsible for national ID cards, biometric records, passports, and residency documentation, was hit by a ransomware attack. The criminal group Green Blood Group claimed responsibility and alleged exfiltration of approximately 139 GB of sensitive data. The incident forced temporary suspension of ID issuance and related services nationwide while authorities worked to contain the breach. Malaysian cybersecurity experts from IRIS Corporation Berhad were dispatched to assist with forensic investigation and recovery.

![alt text](images/senegal1.png)

![alt text](images/senegal2.png)

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Incident Type** | Ransomware Attack with Data Exfiltration |
| **Target Agency** | Directorate of File Automation (DAF), Senegal |
| **Threat Actor** | Green Blood Group |
| **Data Claimed Exfiltrated** | ~139 GB (reports vary: 139 GB to 139 TB) |
| **Systems Affected** | National ID servers, card personalization systems |
| **Response Support** | IRIS Corporation Berhad (Malaysia) |
| **Ransomware Variant** | Not publicly disclosed |

## Affected Products
- Senegal Directorate of File Automation (DAF) systems
- National ID card issuance infrastructure
- Biometric records databases
- Passport and residency documentation systems
- Card personalization servers
- Status: Services suspended / Incident response ongoing

## Technical Details

Internal evidence suggests at least two servers were compromised:

- Unauthorized access to card personalization data on at least one server
- Potential breach of biometric records and citizen identity databases
- Network segmentation insufficient to prevent lateral movement

### Immediate Response Actions
- Cutting network access to affected systems
- Credential rotation across DAF infrastructure
- Blocking connections to foreign mission systems
- Deployment of Malaysian cybersecurity forensic team

### Data Exposure Claims
Green Blood Group claims exfiltration of:

- Citizen records and personal information
- Biometric data (fingerprints, photos)
- Immigration documents
- Passport information
- National ID card data

## Attack Scenario
1. Attackers gain unauthorized access to DAF servers (initial access vector not publicly disclosed)
2. Ransomware is deployed and exfiltration of sensitive data allegedly begins
3. Government detects suspicious activity on critical identity systems
4. DAF systems are shut down and ID services suspended nationwide
5. Incident response teams from IRIS Corporation and internal staff begin containment
6. Investigation and recovery operations commence with foreign mission access blocked

## Impact Assessment

=== "Confidentiality"
    * Alleged exfiltration of citizen records and biometric data
    * Potential exposure of immigration documents and passport information
    * National ID card data claimed stolen by threat actors
    * Government disputes full extent of data theft claims

=== "Integrity"
    * Compromise of card personalization servers
    * Potential tampering with identity databases
    * Government asserts data integrity remains intact despite breach
    * Uncertainty around full extent of system modifications

=== "Availability"
    * National ID and passport issuance suspended nationwide
    * DAF official website remained offline during incident
    * Disruption of identity services affecting millions of residents
    * Civil and economic functions dependent on ID verification interrupted

## Mitigation Strategies

### Short-term Measures
- Implement network segmentation to isolate critical identity systems
- Enforce multi-factor authentication for all privileged access
- Conduct comprehensive security audit of remaining infrastructure
- Monitor for indicators of compromise or reinfection attempts

### Monitoring & Detection
- Deploy enhanced logging and monitoring across identity systems
- Alert on unusual data access or exfiltration patterns
- Track lateral movement indicators in network traffic
- Monitor for unauthorized credential usage
- Implement file integrity monitoring on critical databases

### Long-term Solutions
- **Network Segmentation**: Separate critical identity systems from general IT networks; isolate biometric databases and card personalization servers
- **Robust Backups**: Maintain regular, automated backups stored offline (air-gapped) to prevent ransomware encryption
- **Multi-Factor Authentication**: Enforce MFA for all privileged and remote access; protect administrative interfaces and VPN access
- **Encryption**: Encrypt biometric and identity data at rest and in transit with secure key management
- **Least Privilege**: Apply strict access controls limiting user permissions to only what's necessary
- **Staff Training**: Implement ongoing cybersecurity awareness training for all personnel

## Resources and References

!!! info "Incident Reports"
    - [Senegal shuts National ID office after ransomware attack](https://securityaffairs.com/187811/data-breach/senegal-shuts-national-id-office-after-ransomware-attack.html)
    - [Senegal Cyberattack Disrupts National ID Systems](https://thecyberexpress.com/senegal-cyberattack/)
    - [Senegal National ID Department Suspends Operations Following Green Blood Group Ransomware Attack](https://beyondmachines.net/event_details/senegal-national-id-department-suspends-operations-following-green-blood-group-ransomware-attack-a-t-z-9-a)
    - [Senegal data breach disrupts national ID issuance - Biometric Update](https://www.biometricupdate.com/202602/senegal-data-breach-disrupts-national-id-issuance)
    - [Senegal confirms breach of national ID card department - The Record](https://therecord.media/senegal-breach-national-id-agency)

---

*Last Updated: February 12, 2026* 