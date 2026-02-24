# Mississippi Hospital System Closes All Clinics After Ransomware Attack
![alt text](images/mississippi.png)

**Ransomware**{.cve-chip}  **Healthcare**{.cve-chip}  **Epic EHR**{.cve-chip}  **System Shutdown**{.cve-chip}

## Overview
A ransomware attack hit the University of Mississippi Medical Center (UMMC) in Jackson, forcing one of Mississippi's largest health systems to shut down all approximately 35 outpatient clinics statewide and cancel elective procedures for multiple days. The attack disrupted the Epic electronic health records (EHR) platform, phones, email, and other critical IT systems, leading UMMC to proactively shut down its network to contain the intrusion. While hospitals and emergency departments remained open using manual downtime procedures, the incident demonstrates the severe operational impact ransomware can have on healthcare delivery across an entire state network. UMMC is working with the FBI, CISA, and cybersecurity experts to investigate the intrusion and restore systems.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Victim Organization** | University of Mississippi Medical Center (UMMC) |
| **Organization Type** | Academic medical center, Mississippi's only |
| **Attack Type** | Ransomware with encryption and ransom demands |
| **Initial Detection** | Thursday, February 19, 2026 |
| **Scope** | 7 hospitals + ~35 outpatient clinics statewide |
| **Primary Systems Affected** | Epic EHR, IT network, phones, email, clinical apps |
| **Operational Impact** | All clinics closed, elective procedures canceled |
| **Investigation Partners** | FBI, CISA, DHS, external cybersecurity experts |
| **Ransomware Group** | Not publicly identified (under investigation) |

## Affected Products
- Epic electronic health records (EHR) platform
- Clinical applications (scheduling, imaging, lab systems)
- Internal IT network infrastructure
- Phone and email communication systems
- Outpatient clinic operational systems
- Approximately 35 clinics across Mississippi
- 7 hospitals (emergency and inpatient care)
- Status: Ongoing restoration efforts with federal assistance

## Technical Details

### Attack Characteristics
- **Type**: Ransomware with system encryption
- **Initial Vector**: Unknown (under investigation); likely common healthcare vectors including:
    - Compromised credentials
    - Vulnerable internet-facing services
    - Phishing campaigns targeting staff
    - Unpatched VPN or RDP endpoints
- **Ransom Demands**: Confirmed by UMMC officials; attackers made contact (details not disclosed)
- **Data Exfiltration**: Under investigation; no confirmed PHI theft announced

### Systems Compromised

**Electronic Health Records**:

- Epic EHR platform encrypted and inaccessible
- Patient medical records unavailable through normal workflows
- Clinical documentation forced to paper-based methods
- Historical patient data access severely limited

**Communication Infrastructure**:

- Phone systems disrupted or encrypted
- Email systems affected or shut down proactively
- UMMC forced to use third-party messaging services
- Manual processes required to contact patients for appointment cancellations

**Clinical Support Systems**:

- Scheduling and appointment management systems offline
- Medical imaging systems (PACS) potentially affected
- Laboratory information systems impacted
- Clinical decision support tools unavailable

**IT Network Infrastructure**:

- Core network services encrypted or shut down
- Many clinical applications unavailable
- Internal communication systems degraded
- Network segmentation likely insufficient to prevent spread

### Response Actions Taken

**Immediate Containment (Feb 19, 2026)**:

- Network shutdown to contain ransomware spread
- Activation of Emergency Operations Plan
- Switch to manual/paper procedures for hospitals
- Closure of all outpatient clinics to ensure patient safety

**Forensic Investigation**:

- FBI, CISA, and DHS engaged for federal support
- External cybersecurity experts retained
- Investigation into attack vector and data exposure
- Analysis of ransomware variant and attribution

**Extended Operational Changes**:

- Clinic closures extended through Feb 23-24 (Monday-Tuesday)
- Elective procedures canceled for multiple days
- Emergency departments and inpatient care maintained
- Manual workflows for critical hospital operations

## Attack Scenario
1. **Initial Compromise**: 
    - Attacker gains access to UMMC network through unknown vector
    - Likely methods: compromised credentials, vulnerable VPN/RDP, phishing, or unpatched internet-facing services
    - Initial foothold established in UMMC IT environment

2. **Lateral Movement & Reconnaissance**:
    - Attackers move laterally across UMMC network
    - Enumerate critical systems including Epic EHR platform
    - Identify high-value targets for encryption
    - Map network architecture and data repositories

3. **Privilege Escalation & Persistence**:
    - Attackers escalate privileges to domain administrator or equivalent
    - Establish persistence mechanisms for continued access
    - Prepare for ransomware deployment across multiple systems
    - Position ransomware payloads on key infrastructure

4. **Ransomware Deployment (Feb 19, 2026)**:
    - Coordinated ransomware deployment across UMMC systems
    - Encryption of Epic EHR platform
    - Encryption of core IT services, communication systems
    - Systems across hospitals and clinics affected simultaneously

5. **Detection & Emergency Response**:
    - UMMC detects ransomware activity and encryption
    - Emergency Operations Plan activated immediately
    - Network systems shut down as precautionary measure
    - Hospitals switch to paper workflows and downtime procedures

6. **Operational Impact**:
    - All ~35 outpatient clinics closed statewide due to EHR/scheduling dependency
    - Elective surgeries, chemotherapy sessions, imaging procedures canceled
    - Patients individually contacted for appointment cancellations
    - Emergency departments and hospitals remain open with manual processes

## Impact Assessment

=== "Patient Care Disruption"
    * All 35 outpatient clinics closed for multiple days (Feb 19-24+)
    * Elective surgeries canceled affecting surgical patients
    * Chemotherapy sessions postponed impacting cancer patients
    * Diagnostic imaging procedures rescheduled
    * Ambulatory care completely halted statewide
    * Patients traveled long distances only to find appointments canceled
    * Time-sensitive treatments delayed with potential health consequences

=== "Hospital Operations"
    * Hospitals and emergency departments forced to manual/paper procedures
    * Increased workload and administrative burden on clinical staff
    * Risk of delays in emergency care delivery
    * Reduced efficiency in inpatient care coordination
    * Clinical documentation reverted to paper charts
    * Potential for medication errors or treatment delays due to manual processes

=== "Data Privacy & Security"
    * Protected Health Information (PHI) potentially compromised
    * Investigation ongoing into data exfiltration by attackers
    * Potential HIPAA breach notification requirements if confirmed
    * Risk of patient data exposure or sale on dark web
    * Regulatory scrutiny from HHS Office for Civil Rights
    * Long-term identity theft risk for patients if data stolen

=== "Systemic & Institutional Impact"
    * One attack halted outpatient care across entire state network
    * Demonstrates vulnerability of large health systems to ransomware
    * Federal attention from FBI, CISA, DHS on healthcare resiliency
    * Reputational damage to UMMC as state's only academic medical center
    * Financial losses from canceled procedures and recovery costs
    * Potential ransom payment decision with ethical implications
    * Recovery timeline measured in weeks affecting ongoing operations

## Mitigation Strategies

### Short-term Response (UMMC-Specific)
- **System Isolation**: Keep affected systems offline until forensically validated
- **Downtime Procedures**: Continue hospital operations via manual/paper workflows
- **Federal Coordination**: Maintain collaboration with FBI, CISA, DHS for investigation
- **Patient Communication**: Use alternative channels to reach patients for rescheduling
- **Forensic Analysis**: Complete investigation into attack vector and data exposure
- **Gradual Restoration**: Restore systems incrementally after security validation
- **Staff Support**: Provide resources and training for manual workflow procedures

### Ransomware Defense (Healthcare Providers)
- **Multi-Factor Authentication**: Enforce MFA on all remote access (VPN, RDP, email, EHR)
- **Patch Management**: Maintain aggressive patching schedule for all systems and applications
- **Service Hardening**: Harden exposed services including VPNs, RDP, email gateways, and web applications
- **Credential Security**: Implement strong password policies and monitor for credential compromise
- **Email Security**: Deploy advanced email filtering and anti-phishing technologies
- **Endpoint Protection**: Use advanced endpoint detection and response (EDR) on all devices

### Backup & Recovery
- **Offline Backups**: Maintain segregated, tested offline backups of critical systems (EHR, imaging, scheduling)
- **Backup Testing**: Regularly test backup restoration procedures and validate integrity
- **Immutable Backups**: Use immutable backup storage to prevent ransomware encryption
- **Geographic Diversity**: Store backups in physically separate locations from production
- **Recovery Time Objectives**: Establish and practice RTOs for critical healthcare systems
- **Downtime Procedures**: Rehearse incident-response and downtime procedures regularly

### Network Architecture
- **Network Segmentation**: Implement robust segmentation preventing IT compromise from affecting clinical systems
- **Zero Trust**: Apply zero trust principles to healthcare network architecture
- **Micro-Segmentation**: Isolate critical clinical systems (Epic EHR, PACS, lab systems)
- **Least Privilege**: Enforce least privilege access across all systems and user accounts
- **Egress Filtering**: Implement strict egress filtering to detect data exfiltration

## Resources and References

!!! info "Incident Reports"
    - [Mississippi Hospital System Closes All Clinics After Ransomware Attack - SecurityWeek](https://www.securityweek.com/mississippi-hospital-system-closes-all-clinics-after-ransomware-attack/)
    - [Mississippi hospital system closes all clinics after ransomware attack](https://www.news4jax.com/health/2026/02/20/mississippi-hospital-system-closes-all-clinics-after-ransomware-attack/)
    - [Mississippi Hospital System Closes All Clinics After Ransomware Attack](https://www.usnews.com/news/best-states/mississippi/articles/2026-02-20/mississippi-hospital-system-closes-all-clinics-after-ransomware-attack)
    - [Mississippi hospital system closes all clinics after ransomware attack - ABC News](https://abcnews.com/Health/wireStory/mississippi-hospital-system-closes-clinics-after-ransomware-attack-130337447)
    - [Ransomware Attack Forces Closure Of All University Of Mississippi Clinics - KFF Health News](https://kffhealthnews.org/morning-breakout/ransomware-attack-forces-closure-of-all-university-of-mississippi-clinics/)
    - [Mississippi health system closes all clinics after cyberattack - NPR](https://www.npr.org/2026/02/21/nx-s1-5721746/mississippi-health-system-ransomware-attack)

---

*Last Updated: February 24, 2026* 