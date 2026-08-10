# UNC6671 Vishing & Data-Extortion Campaign
![alt text](images/Vishing.png)

**UNC6671**{.cve-chip} **Voice Phishing (Vishing)**{.cve-chip} **AiTM Phishing**{.cve-chip} **SaaS Data Theft**{.cve-chip} **Cloud Extortion**{.cve-chip}

## Overview

UNC6671 is a financially motivated threat actor specializing in voice phishing (vishing) and cloud/SaaS data theft. The group previously operated under the BlackFile extortion brand.

Although BlackFile announced its shutdown in May 2026, Google Threat Intelligence Group identified continued activity associated with Redact, Pink, Helix, and Falcon, indicating that the operation likely continued through rebranding rather than disappearing.

## Technical Details

Attackers impersonate internal IT/helpdesk personnel and contact employees, often through personal mobile phones. Victims are persuaded to perform an urgent MFA, passkey, or security migration and are redirected to attacker-controlled credential-harvesting websites.

UNC6671 uses adversary-in-the-middle (AiTM) phishing proxies to capture credentials and authentication sessions. Compromised access is then used against Microsoft 365, Okta, SharePoint, OneDrive, and other SaaS applications.

The attackers have used Python and PowerShell, Microsoft Graph APIs, and captured session cookies such as FedAuth to automate data theft. In some cases, activity appeared as FileAccessed rather than FileDownloaded, potentially reducing detection visibility.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Threat Actor** | UNC6671 |
| **Campaign Type** | Vishing-enabled credential theft and data extortion |
| **Primary Initial Access** | IT/helpdesk impersonation via phone calls |
| **Credential Capture Method** | AiTM phishing and session interception |
| **Primary Target Platforms** | Microsoft 365, Okta, SharePoint, OneDrive, and related SaaS |
| **Observed Tooling** | Python, PowerShell, Microsoft Graph APIs |
| **Notable Artifacts** | Captured FedAuth session cookies |
| **Detection Challenge** | Cloud access activity may appear as FileAccessed instead of FileDownloaded |

## Affected Products

- Microsoft 365 tenant identities and services
- Okta-managed enterprise identities
- SharePoint Online document repositories
- OneDrive enterprise storage
- Other connected SaaS applications with sensitive business data

## Attack Scenario

1. Attacker identifies an employee.
2. Employee receives a phone call from someone impersonating IT/helpdesk.
3. Attacker claims that a mandatory MFA, passkey, or security migration is required.
4. Employee follows a malicious link to a fake SSO portal.
5. AiTM infrastructure captures credentials and authentication/session information.
6. Attacker uses the compromised identity to access Microsoft 365/Okta and connected SaaS applications.
7. Sensitive documents are identified using cloud search and automated scripts.
8. Data is exfiltrated to attacker-controlled infrastructure.
9. Victim receives an extortion demand and is threatened with data disclosure.

## Impact Assessment

=== "Integrity"

    - Unauthorized access enables attacker-driven changes to cloud content, permissions, and collaboration settings
    - Compromised identities can be used to alter governance controls and reduce trust in business records
    - Malicious use of API access may tamper with audit trails or data handling workflows

=== "Confidentiality"

    - Confidential documents and customer or employee information can be exfiltrated at large scale
    - Intellectual property and financial data are at high risk once SaaS identities are hijacked
    - Google observed one case where scripts accessed more than one million files across SharePoint and OneDrive

=== "Availability"

    - Incident containment can require account lockouts, token revocation, and temporary service restrictions
    - Business operations may be disrupted while access rights, integrations, and secrets are remediated
    - Extortion pressure can force emergency response actions with productivity and service impact

## Mitigation Strategies

### Identity Hardening

- Implement phishing-resistant MFA such as FIDO2 security keys and passkeys.
- Strengthen Conditional Access policies and enforce high-assurance sign-in controls.

### Operational Procedures

- Establish strict procedures preventing IT/helpdesk staff from requesting credentials or MFA actions through unsolicited calls.
- Train employees to recognize IT impersonation and vishing social-engineering patterns.

### Monitoring and Detection

- Monitor identity provider logs for anomalous authentication and MFA events.
- Monitor Microsoft 365, SharePoint, and OneDrive for unusual bulk access and abnormal FileAccessed activity.
- Alert on suspicious user-agent mismatches and access from VPN or hosting infrastructure.

### Incident Response

- Revoke compromised sessions and tokens immediately.
- Review OAuth and application permissions following suspected compromise.
- Rotate exposed credentials and reassess trust in affected SaaS integrations.

## Resources and References

!!! info "Public Reporting"
    - [Vishing Extortion Group UNC6671 Rebrands After Making Millions - SecurityWeek](https://www.securityweek.com/vishing-extortion-group-unc6671-rebrands-after-making-millions/)
    - [UNC6671 Rebrands: Multi-Brand Vishing Extortion Targets Financial Services and Enterprise Cloud Environments | Google Cloud Blog](https://cloud.google.com/blog/topics/threat-intelligence/unc6671-targets-financial-services-and-enterprise-cloud-environments)

---

*Last Updated: August 10, 2026*
