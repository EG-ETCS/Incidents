# Times Car Data Breach
![alt text](images/Times.png)

**Times Mobility**{.cve-chip} **Times Car**{.cve-chip} **Personal Data Breach**{.cve-chip} **6.6M Accounts**{.cve-chip} **Japan Privacy Incident**{.cve-chip}

## Overview

Times Mobility, operator of the Times Car service, confirmed unauthorized access to a web system affecting information tied to approximately 6.6 million accounts. Reported scope includes current and former members as well as incomplete account applications.

At disclosure time, the company reported no confirmed leakage of credit-card information and no confirmed misuse of the exposed data.

## Technical Details

### Confirmed Incident Context

- Unauthorized access occurred in a Times Car web system.
- Personal information associated with around 6.6 million accounts was potentially affected.
- Public reporting has not disclosed the precise initial intrusion vector.

### Potentially Affected Data Fields

- Names
- Addresses
- Dates of birth
- Telephone numbers
- Email addresses
- Driver's-license details and image data
- Passwords stored in non-restorable form
- Linked-service identifiers

### Investigation Status

- Root-cause/entry-point analysis remained ongoing in initial reporting.
- Company disclosures focused on containment and regulatory/law-enforcement notification actions.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Organization** | Times Mobility (Times Car) |
| **Incident Type** | Unauthorized access / data breach |
| **Estimated Affected Accounts** | Approximately 6.6 million |
| **Primary Exposed Domain** | Customer/member web-system data |
| **Payment-Card Exposure** | No confirmed credit-card leakage reported at disclosure |
| **Publicly Disclosed Initial Vector** | Not disclosed at time of reporting |

## Affected Products

- Times Car web-system environment handling member and applicant account information.
- Data stores associated with account registration, identity, and contact records.

## Attack Scenario

1. External attacker gains unauthorized access to Times Car web-system environment.
2. Attacker accesses stored customer/member/applicant information.
3. Large volumes of account-linked records are extracted.
4. Stolen data may be leveraged for phishing, social engineering, identity abuse, and follow-on account attacks.

## Impact Assessment

=== "Reported Impact"

    - Approximately 6.6 million accounts potentially affected
    - Exposure included sensitive personal and identity-verification information
    - No confirmed credit-card leakage at disclosure time

=== "Potential Risk"

    - Targeted phishing and impersonation campaigns
    - Identity fraud and account-abuse attempts
    - Broader follow-on attacks using linked personal attributes

=== "Criticality"

    - **High** due to scale and sensitivity of exposed personal data, despite no confirmed card-data leakage in the initial disclosure

## Mitigation Strategies

### Immediate Containment

- Block the unauthorized access route.
- Block communication paths tied to the identified attack source.
- Monitor systems for further unauthorized behavior.

### Investigation and Response

- Conduct full forensic investigation and preserve relevant evidence/logs.
- Determine root cause and complete attack-path reconstruction.
- Identify all impacted datasets and account populations.

### Notification and Regulatory Coordination

- Notify potentially affected users.
- Report incident details to Japan's Personal Information Protection Commission and law-enforcement authorities.

### Recovery and Hardening

- Implement recurrence-prevention controls based on forensic findings.
- Strengthen web-system access controls, monitoring, and anomaly detection.
- Reassess segmentation and least-privilege boundaries for sensitive customer-data systems.

## Resources and References

!!! info "Public Reporting"
    - [Times Car confirms data breach affecting 6.6 million user accounts](https://www.bleepingcomputer.com/news/security/times-car-confirms-data-breach-affecting-66-million-user-accounts/)

---

*Last Updated: September 29, 2026*
