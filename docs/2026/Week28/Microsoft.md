# Fake Microsoft Entra Passkey Enrollment Vishing Campaign
![alt text](images/Microsoft.png)

**Vishing**{.cve-chip} **Microsoft Entra**{.cve-chip} **Passkey Abuse**{.cve-chip} **FIDO2/WebAuthn**{.cve-chip} **Account Persistence**{.cve-chip}

## Overview

Researchers identified a sophisticated social engineering campaign in which attackers impersonate Microsoft or corporate IT support over the phone to convince victims to complete a fake Microsoft Entra passkey enrollment process. Instead of exploiting software vulnerabilities, attackers abuse legitimate Microsoft Entra authentication features to register attacker-controlled FIDO2/WebAuthn passkeys on victim accounts, enabling persistent unauthorized access.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Threat Actor** | O-UNC-066 |
| **Primary Technique** | Voice phishing (vishing) and real-time session relay |
| **Abused Platform** | Microsoft Entra / Microsoft 365 identity workflow |
| **Abused Feature** | Legitimate FIDO2/WebAuthn passkey enrollment |
| **Initial Lure** | Phone call impersonating Microsoft or internal IT support |
| **Credential Capture** | Fake Microsoft Entra enrollment portal phishing page |
| **Persistence Method** | Registration of rogue attacker-controlled passkey |
| **Malware Requirement** | None (identity feature abuse and social engineering) |
| **Post-Reset Risk** | Access can persist after password change if rogue passkey remains |

## Affected Products

- Microsoft 365 tenant accounts susceptible to social engineering
- Microsoft Entra identities without strict authentication-method governance
- Organizations lacking monitoring on passkey/FIDO2 method registrations
- Privileged cloud/admin accounts where compromised authentication methods are high-impact

## Attack Scenario

1. An attacker calls the victim while impersonating Microsoft or corporate IT support.
2. The victim is told security verification or passkey enrollment is required.
3. The victim visits a fake Microsoft Entra enrollment page.
4. The victim enters credentials and approves MFA prompts.
5. The attacker relays the authenticated session to Microsoft in real time.
6. The attacker registers an attacker-controlled FIDO2/WebAuthn passkey on the victim account.
7. The attacker uses the newly registered passkey for persistent access to Microsoft 365 resources.

## Impact Assessment

=== "Integrity"

    - Attackers can manipulate mailbox rules, files, and collaboration settings from compromised accounts
    - Business processes may be altered via unauthorized account actions
    - Privileged account compromise can affect tenant-wide security posture

=== "Confidentiality"

    - Unauthorized access to Outlook, Teams, SharePoint, and OneDrive data
    - Theft of confidential emails, documents, and internal communications
    - Increased risk of BEC and downstream fraud using trusted identities

=== "Availability"

    - Account recovery and incident response can disrupt user productivity
    - Defensive containment may require temporary access restrictions and auth-method resets
    - Tenant operations can be degraded during broad identity remediation

## Mitigation Strategies

### Immediate Actions

- Train users to recognize vishing and fake IT support calls
- Communicate that Microsoft will not request passkey enrollment via unsolicited phone calls
- Review and remove unauthorized authentication methods immediately

### Short-term Measures

- Implement Conditional Access and Microsoft Entra Identity Protection policies
- Require enhanced approvals or strong controls for new authentication method registration where possible
- Conduct immediate authentication-method audits for privileged and high-risk accounts

### Monitoring & Detection

- Monitor Microsoft Entra audit logs for new FIDO2/passkey registrations
- Alert on unusual enrollments, new devices, and anomalous login behavior
- Correlate phone-based social engineering reports with authentication changes and session anomalies

### Long-term Solutions

- Establish recurring governance reviews of registered authentication methods tenant-wide
- Harden identity lifecycle controls for admin and executive accounts
- Integrate identity-threat detections into SOC playbooks focused on account persistence abuse

## Resources and References

!!! info "Public Reporting"
    - [Hackers Use Fake Microsoft Entra Passkey Enrollment to Gain Microsoft 365 Access](https://thehackernews.com/2026/07/hackers-use-fake-microsoft-entra.html)

---

*Last Updated: July 12, 2026*
