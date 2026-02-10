# Fortinet FortiCloud SSO Login Authentication Bypass Vulnerabilities
![FortiCloud](images/forticloud.png)

**CVE-2025-59718**{.cve-chip}
**CVE-2025-59719**{.cve-chip}
**Authentication Bypass**{.cve-chip}

## Overview
Multiple Fortinet products contain critical authentication bypass vulnerabilities in the FortiCloud Single Sign-On (SSO) login feature. Improper verification of cryptographic signatures in SAML-based authentication allows a remote, unauthenticated attacker to bypass authentication and gain administrative access by submitting a crafted SAML response. These vulnerabilities affect FortiOS, FortiProxy, FortiSwitchManager, and FortiWeb products when FortiCloud SSO is enabled. Successful exploitation could result in full administrative compromise of affected devices, modification of security configurations, and potential lateral movement within enterprise networks.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **CVE IDs** | CVE-2025-59718, CVE-2025-59719 |
| **Vulnerability Type** | Improper Verification of Cryptographic Signature (CWE-347) |
| **Attack Vector** | Network (remote) |
| **Authentication** | None required |
| **Complexity** | Low |
| **User Interaction** | Not required |
| **Affected Feature** | FortiCloud SSO (SAML-based authentication) |
| **Severity** | Critical |

## Affected Products

### FortiOS
- **Vulnerable Versions**: Versions prior to patches
- **Fixed Versions**: 7.6.4+, 7.4.9+, 7.2.12+, 7.0.18+

### FortiProxy
- **Vulnerable Versions**: Versions prior to patches
- **Fixed Versions**: 7.6.4+, 7.4.11+, 7.2.15+, 7.0.22+

### FortiSwitchManager
- **Vulnerable Versions**: Versions prior to patches
- **Fixed Versions**: 7.2.7+, 7.0.6+

### FortiWeb
- **Vulnerable Versions**: Versions prior to patches
- **Fixed Versions**: 8.0.1+, 7.6.5+, 7.4.10+

### Prerequisite for Exploitation
- **FortiCloud SSO must be enabled** on the affected device

## Vulnerability Details
![](images/forticloud1.png)
### Improper Verification of Cryptographic Signature (CWE-347)
The vulnerabilities stem from insufficient validation of SAML (Security Assertion Markup Language) assertion signatures in the FortiCloud SSO authentication process. SAML is an XML-based protocol for exchanging authentication and authorization data between parties.

### Root Cause
When processing SAML authentication responses from FortiCloud SSO, the affected Fortinet products fail to properly verify the cryptographic signatures that validate the authenticity of the SAML assertions. This allows attackers to forge SAML responses that appear legitimate to the vulnerable system.

### SAML Authentication Bypass Mechanism
1. SAML responses contain assertions about a user's identity and attributes
2. These assertions should be cryptographically signed to prevent tampering
3. The receiving system (Fortinet device) should verify the signature before trusting the assertion
4. The vulnerability allows bypass of this signature verification
5. Attackers can craft SAML responses claiming administrative privileges
6. The system accepts the forged response and grants access

## Attack Scenario
1. **Reconnaissance**: Attacker identifies a Fortinet device (firewall, proxy, WAF, switch manager) with FortiCloud SSO authentication enabled
2. **SAML Response Crafting**: Attacker crafts a malicious SAML authentication response claiming to be an administrator user from FortiCloud
3. **Signature Verification Bypass**: The vulnerable Fortinet product fails to properly verify the SAML signature, accepting the forged response as valid
4. **Authentication Bypass**: The forged SAML response is accepted as legitimate authentication
5. **Administrative Access**: Attacker gains full administrative access to the Fortinet device without any credentials
6. **Persistence & Lateral Movement**: Attacker modifies configurations, creates backdoor accounts, disables security controls, or uses the compromised device for lateral movement

## Impact Assessment

=== "Integrity"
    * Full administrative compromise of Fortinet devices
    * Unauthorized modification of firewall rules and policies
    * Alteration of proxy, WAF, or switch configurations
    * Creation of persistent backdoor administrator accounts
    * Disabling of security controls and logging

=== "Confidentiality"
    * Access to network configuration and topology
    * Exposure of VPN credentials and certificates
    * Visibility into security policies and rules
    * Access to traffic logs and monitoring data
    * Potential interception of network traffic

=== "Availability"
    * Disruption of network security services
    * Denial of service through misconfiguration
    * Blocking of legitimate traffic
    * Service degradation or outage
    * Loss of security monitoring capabilities

=== "Enterprise Impact"
    * **Critical Infrastructure**: Fortinet devices often protect critical network perimeters
    * **Widespread Deployment**: Many organizations use Fortinet products extensively
    * **Compliance Violations**: Security control bypass impacts regulatory compliance
    * **Trust Boundary Collapse**: Compromise of trusted security infrastructure
    * **Supply Chain**: Managed service providers using Fortinet may affect multiple clients

## Mitigation Strategies

### 🔄 Immediate Actions
- **Apply Security Patches**: Upgrade to fixed Fortinet versions immediately
    - FortiOS: 7.6.4+, 7.4.9+, 7.2.12+, 7.0.18+
    - FortiProxy: 7.6.4+, 7.4.11+, 7.2.15+, 7.0.22+
    - FortiSwitchManager: 7.2.7+, 7.0.6+
    - FortiWeb: 8.0.1+, 7.6.5+, 7.4.10+
- **Disable FortiCloud SSO**: Temporarily disable FortiCloud SSO until patches are applied
- **Access Restriction**: Limit management interface access to trusted networks only
- **Emergency Audit**: Review administrator accounts for unauthorized additions

### 🛡️ Access Control Hardening
- **Management Network Isolation**: Restrict management interfaces to dedicated admin networks
- **IP Whitelisting**: Allow management access only from specific trusted IP addresses
- **VPN Requirement**: Require VPN access for all remote management
- **Multi-Factor Authentication**: Use local MFA in addition to or instead of SSO
- **Least Privilege**: Review and limit administrative account permissions

### 🔍 Monitoring & Detection
- **Log Review**: Examine authentication logs for suspicious admin login activity
- **Anomaly Detection**: Monitor for unusual login patterns or times
- **Configuration Changes**: Alert on unauthorized configuration modifications
- **Account Auditing**: Review all administrator accounts for unauthorized creation
- **SAML Monitoring**: Log and analyze SAML authentication attempts
- **Baseline Comparison**: Compare current configurations against known-good baselines

## Resources and References

!!! info "Official Documentation"
    - [AL25-019 - Vulnerabilities impacting Fortinet products - FortiCloud SSO Login Authentication Bypass | Canadian Centre for Cyber Security](https://www.cyber.gc.ca/en/alerts-advisories/al25-019-vulnerabilities-impacting-fortinet-products-forticloud-sso-login-authentication-bypass-cve-2025-59718-cve-2025-59719)
    - [NVD - CVE-2025-59718](https://nvd.nist.gov/vuln/detail/CVE-2025-59718)
    - [NVD - CVE-2025-59719](https://nvd.nist.gov/vuln/detail/CVE-2025-59719)
    - [CWE - CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
    - [PSIRT | FortiGuard Labs](https://www.fortiguard.com/psirt/FG-IR-25-647)
    - [Critical Vulnerabilities in Multiple Fortinet Products | Cyber Security Agency of Singapore](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2025-116/)
    - [Critical vulnerabilities in multiple Fortinet products - FortiCloud SSO Login Authentication Bypass | Cyber.gov.au](https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/critical-vulnerabilities-in-multiple-fortinet-products-forticloud-sso-login-authentication-bypass)
    - [Fortinet authentication bypass vulnerabilities CVE-2025-59718 & CVE-2025-59719](https://www.triskelelabs.com/blog/fortinet-authentication-bypass-vulnerabilities-cve-2025-59718-cve-2025-59719)
    - [Fortinet Patches Critical Authentication Bypass Vulnerabilities - SecurityWeek](https://www.securityweek.com/fortinet-patches-critical-authentication-bypass-vulnerabilities/)
    - [Fortinet fixed two critical authentication-bypass vulnerabilities](https://securityaffairs.com/185546/security/fortinet-fixed-two-critical-authentication-bypass-vulnerabilities.html)

!!! danger "Critical Warning"
    These vulnerabilities allow **unauthenticated remote attackers** to gain **full administrative access** to Fortinet security devices. Organizations using FortiCloud SSO should treat this as a critical security incident. Immediate patching or SSO disablement is essential.

