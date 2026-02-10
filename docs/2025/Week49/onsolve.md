# OnSolve CodeRED Ransomware Attack
![OnSolve CodeRED](images/onsolve.png)

**Ransomware Attack**{.cve-chip}  
**INC Ransom**{.cve-chip}  
**Emergency Alert System**{.cve-chip}

## Overview

The vendor (Crisis24, operating the CodeRED platform) suffered a ransomware attack by the threat group **INC Ransom**. As a result: the "legacy" CodeRED alert system environment was compromised and taken offline; many local governments and law-enforcement agencies lost the ability to send emergency alerts. User data tied to the legacy system — names, addresses, email addresses, phone numbers, and account passwords — was exfiltrated. The vendor decided to decommission the legacy platform and migrate clients to a new, separate platform.

## Technical Specifications

| **Attribute**           | **Details**                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| **Threat Actor**        | INC Ransom                                                                  |
| **Target Organization** | Crisis24 / OnSolve (CodeRED platform)                                       |
| **Attack Type**         | Ransomware + Data Exfiltration + Service Disruption of Emergency Alert System                           |
| **Initial Access**      | November 1, 2025                                                            |
| **Ransomware Deployment** | November 10, 2025                                                         |
| **Impact Scope**        | Multiple U.S. states, hundreds of municipalities and public-safety agencies |

## Technical Details

### Attack Timeline
- **November 1, 2025**: Initial unauthorized access occurred
- **November 10, 2025**: File-encrypting ransomware deployed

### Security Weaknesses Exploited
- Legacy CodeRED environment **lacked adequate segmentation**
- **Weak credential practices** (e.g., storing passwords in **plain text**)
- **Outdated backups**: Last good backup reportedly from **March 31, 2025**
  - Customer accounts and data created or modified after that date are likely lost or require re-registration

### Attacker Actions
- Published screenshots of stolen data on their **dark-web leak site**
- Reportedly offered stolen data for sale
- Demanded ransom; when negotiations failed, escalated to data leak threats

### Exfiltrated Data
- Names
- Addresses
- Email addresses
- Phone numbers
- Account passwords (stored in plain text)

## Attack Scenario

This was a classic **ransomware + data-exfiltration + double-extortion** scenario:

1. **Initial Access (Nov 1, 2025)**: Attackers gained access to the vendor's legacy CodeRED environment.

2. **Lateral Movement**: Moved laterally or escalated privileges (likely facilitated by weak credential and segmentation practices).

3. **Data Exfiltration**: Exfiltrated user data (names, addresses, emails, phones, passwords).

4. **Ransomware Deployment (Nov 10, 2025)**: Deployed encryption to disable alerting systems.

5. **Ransom Demand**: Demanded US $100,000; negotiations failed.

6. **Data Leak Threat**: Published a data leak site entry for CodeRED, showing some stolen data and threatening to sell more.

7. **Vendor Response**: After the attack, the vendor shut down the legacy environment and forced a migration to a new, separate platform.

Because the legacy platform was still in **live use across many municipalities** — a centralized single-vendor SaaS — the outage had **widespread impact**.

## Impact Assessment

=== "Emergency Alert Disruption"
    * Disruption of emergency alert services (phone call, SMS, email, push) for many municipalities and public-safety agencies across **multiple U.S. states**
    * Communities unable to receive timely notifications about:
        - Floods
        - Fires
        - Chemical spills
        - Evacuations
        - Missing-person alerts
        - Other emergencies

=== "Data Breach"
    * Exfiltration of sensitive personal data for potentially **hundreds of thousands of users**
    * Risk of identity theft, credential reuse attacks, phishing, and other privacy/security threats
    * Passwords stored in **plain text** now exposed

=== "Loss of Functionality"
    * The legacy platform was **permanently decommissioned**
    * Many local agencies lost their alerting channel until they migrated to the new platform
    * Some municipalities **terminated their contracts entirely**

=== "Data Loss"
    * Available backups dated from **March 2025**
    * Any user accounts or updates since then may be lost
    * Requiring re-registration or manual recovery

=== "Trust & Confidence"
    * Erosion of public trust in third-party alert systems
    * Government agencies reassessing vendor risk for critical infrastructure
    * Long-term impact on emergency notification adoption

## Mitigations

### 🔄 Vendor Response
- **Decommissioned** the compromised legacy platform
- Accelerated rollout of a **new, separate platform**
- Migrated customers over

### 🔒 For Users
- **Change passwords** immediately, especially if reused across multiple sites
- Enable **stronger authentication** where possible
- Monitor for phishing attempts using exposed personal information

### 🏢 For Municipalities / Agencies
- Adopt **backup / fallback alerting channels**:
  - Traditional media
  - Door-to-door notifications
  - Alternative platforms
- Avoid **single-vendor dependency** for critical alerts

### 🛡️ Vendor Risk Management
- Conduct **robust vendor risk assessments**
- Require **network segmentation**
- Ensure **proper credential storage** (no plain-text passwords)
- Mandate **multi-factor authentication (MFA)**
- Regular **penetration testing / audits** for critical infrastructure vendors

### 🏗️ Public-Safety Sector Overall
- Treat third-party SaaS alerting platforms as **critical infrastructure**
- Build **redundancy** into emergency notification systems
- Develop **incident response plans**
- Establish **backup communication channels**
- Conduct **regular security reviews** of any vendor providing alerting or critical services

## Resources & References

!!! info "Media Coverage & Analysis"
    * [Hack of OnSolve CodeRED Platform Disrupts Emergency Alert Systems – HackMag](https://hackmag.com/news/codered)
    * [FCC says hackers hijack US radio gear to send fake alerts, obscenities | Reuters](https://www.reuters.com/world/us/fcc-says-hackers-hijack-us-radio-gear-send-fake-alerts-obscenities-2025-11-26/)
    * [Crisis24 shuts down emergency notification system in wake of ransomware attack | CyberScoop](https://cyberscoop.com/crisis24-onsolve-codered-emergency-system-ransomware/)
    * [CodeRED Cyberattack Disrupts Alerts - CyberMaterial](https://cybermaterial.com/codered-cyberattack-disrupts-alerts/)
    * [CodeRED Ransomware Attack: How INC Ransom Crippled America's Emergency Alert System - ctrlaltnod](https://www.ctrlaltnod.com/en/news/cybersecurity/codered-ransomware-attack/)
    * [Ransomware Attack Disrupts Local Emergency Alert System Across US - SecurityWeek](https://www.securityweek.com/ransomware-attack-disrupts-local-emergency-alert-system-across-us/)
    * [CodeRED platform attack affects thousands of organizations nationwide](https://www.wvva.com/2025/11/26/codered-platform-attack-affects-thousands-organizations-nationwide/)
    * [Emergency alert systems across US disrupted following OnSolve CodeRED cyberattack | TechRadar](https://www.techradar.com/pro/security/emergency-alert-systems-across-us-disrupted-following-onsolve-codered-cyberattack)