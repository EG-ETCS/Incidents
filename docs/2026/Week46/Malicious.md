# Optimizely Supply Chain Attack – Malicious JavaScript Injection Targeting Major Websites
![alt text](images/Malicious.png)

**Supply Chain Attack**{.cve-chip}  
**Malicious JavaScript**{.cve-chip}  
**Data Theft**{.cve-chip}

## Overview

Attackers exploited a vulnerability in Optimizely's account registration process to inject malicious JavaScript into customer projects. The compromised scripts were distributed through Optimizely's legitimate content delivery infrastructure (CDN), exposing visitors to affected websites to malicious activities. Researchers identified 188 infected JavaScript files across 178 organizations, including major websites such as CNN, BBC, Fox News, Zoom, and Salesforce. The attack demonstrated the severe risk posed by supply chain vulnerabilities in widely-used third-party services, with malicious payloads designed to steal payment card information, hijack cryptocurrency wallets, and target vulnerable iOS devices.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Attack Type** | Supply Chain Attack / Malicious JavaScript Injection |
| **Vulnerable Component** | Optimizely Experimentation account signup flow |
| **Delivery Method** | Optimizely's legitimate CDN (cdn.optimizely.com) |
| **Malicious Domain** | 1688360[.]cc |
| **Malicious Script** | /track.js |
| **Data Exfiltration Endpoint** | /card.php |
| **Obfuscation Method** | Base64 encoding and JavaScript atob() function |
| **Affected Organizations** | 178 organizations |
| **Compromised Files** | 188 JavaScript files |
| **Exploit Kits Involved** | Coruna and DarkSword |
| **iOS Targeting** | Vulnerable iPhone and iPad versions |

## Affected Products

- Optimizely Experimentation platform (vulnerable signup process)
- Major websites using Optimizely services:
  - CNN
  - BBC
  - Fox News
  - Zoom
  - Salesforce
  - 173 additional organizations
- Vulnerable iOS devices (iPhones and iPads with outdated security patches)

## Attack Scenario

1. Attackers exploited a vulnerability in Optimizely's Experimentation account signup flow
2. Gained the ability to inject malicious JavaScript into customer projects
3. Malicious scripts were distributed through Optimizely's legitimate CDN infrastructure
4. Visitors accessing affected websites loaded and executed the injected JavaScript in their browsers
5. The malware attempted to collect payment-card information, monitor cryptocurrency wallet addresses, and gather browser data
6. Targeted Apple devices were exposed to additional exploit payloads through the Coruna and DarkSword exploit kits
7. Data was exfiltrated to malicious infrastructure controlled by attackers

## Impact Assessment

=== "Confidentiality"
    * Potential theft of payment-card information from website visitors
    * Collection of sensitive browsing data and session information
    * Exposure of cryptocurrency wallet addresses and transaction data
    * Browser fingerprinting and device information disclosure
    * User credentials and personal data at risk

=== "Integrity"
    * Cryptocurrency wallet address replacement and hijacking
    * Modification of website content through malicious JavaScript injection
    * Compromise of legitimate CDN distribution channel
    * Alteration of user transactions and interactions
    * iOS device compromise and system manipulation

=== "Availability"
    * Potential disruption of affected websites through resource consumption
    * Browser performance degradation from malicious script execution
    * Network bandwidth consumption from exfiltration activities
    * iOS device functionality impact from exploit payload execution
    * Service degradation on major international websites

## Mitigation Strategies

### Immediate Actions
- Optimizely blocked the vulnerable signup process and deployed security fixes
- Remove malicious JavaScript from affected customer projects
- Invalidate and regenerate all Optimizely API tokens and authentication credentials
- Terminate active sessions and force user re-authentication
- Block outbound connections to malicious domain 1688360[.]cc at network perimeter

### Short-term Measures
- Review Optimizely account access logs and permissions
- Revoke compromised credentials and rotate potentially exposed secrets
- Audit all third-party JavaScript dependencies integrated into websites
- Review CDN integrations and implement access controls
- Conduct security assessments of Optimizely implementation in customer environments
- Implement Content Security Policy (CSP) headers to restrict unauthorized script execution

### Monitoring & Detection
- Monitor network traffic for connections to 1688360[.]cc and related malicious infrastructure
- Review website access logs for suspicious activity patterns
- Implement intrusion detection systems (IDS) to identify malicious JavaScript execution
- Monitor payment-card transactions for unauthorized charges or fraud
- Monitor cryptocurrency wallets for address replacement or unauthorized transfers
- Alert on creation of new API tokens or unexpected permission changes
- Track iOS device exploitation attempts and malicious payload delivery

### Long-term Solutions
- Implement strong supply chain security practices for third-party vendors
- Establish vendor security requirements and audit procedures
- Develop incident response plan for supply chain attack scenarios
- Implement software composition analysis (SCA) tools to monitor dependencies
- Update iOS devices to the latest available security versions
- Establish continuous security monitoring and threat intelligence feeds
- Conduct regular security audits of third-party integrations
- Implement zero-trust architecture for third-party script execution
- Establish vendor communication and notification procedures for security incidents

## Resources and References

!!! info "Official Sources"
    - [Optimizely hack infected CNN, Fox News, BBC, Salesforce sites with malware | Bleeping Computer](https://www.bleepingcomputer.com/news/security/optimizely-supply-chain-attack-delivers-malware-to-cnn-fox-news-bbc-salesforce-sites/)

---

*Last Updated: November 17, 2026*
