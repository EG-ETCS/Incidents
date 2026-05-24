# Trump Mobile Customer Data Exposure
![alt text](images/TrumpMobile.png)

**Data Exposure**{.cve-chip} **Broken Access Control**{.cve-chip} **IDOR Risk**{.cve-chip} **Ecommerce Security**{.cve-chip}

## Overview
A vulnerability on the Trump Mobile preorder website reportedly exposed customer information associated with orders for the "T1" smartphone. Researchers and media outlets reported that unauthorized users could access customer records through insecure web/API functionality.

Exposed data allegedly included customer names, email addresses, phone numbers, home addresses, and order information.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Incident Type** | Customer data exposure via web/API weakness |
| **Likely Root Cause** | Weak backend authorization and insecure API design |
| **Likely CWE Class** | Broken Access Control and/or Insecure Direct Object Reference (IDOR) |
| **Attack Method** | Parameter manipulation in HTTP/API requests |
| **Authentication Control Failure** | Missing/insufficient server-side authorization validation |
| **Exposed Data (Reported)** | Name, email, phone, home address, order details |
| **No Evidence Reported Of** | Payment card data or Social Security number exposure |

## Affected Products
- Trump Mobile preorder website and related order-management APIs
- Customer/order lookup endpoints exposed to untrusted networks
- Backend services permitting record enumeration by predictable identifiers

## Attack Scenario
1. **Endpoint Discovery**:
   An attacker identifies publicly accessible API endpoints on the Trump Mobile preorder site.

2. **Parameter Manipulation**:
   The attacker modifies request parameters such as order IDs or customer identifiers.

3. **Authorization Bypass**:
   Due to missing authorization validation, the backend returns customer data linked to other users.

4. **Bulk Enumeration**:
   The attacker automates requests to enumerate and scrape large volumes of records.

5. **Follow-On Abuse**:
   Stolen information is used for phishing, social engineering, SIM-swap attacks, or identity profiling.

## Impact Assessment

=== "Privacy and Security"
    * Exposure of personally identifiable information (PII)
    * Elevated risk of phishing, SMS fraud, and account-takeover pretexting
    * Increased identity profiling risk for targeted scams

=== "Business and Compliance"
    * Reputational damage during a high-profile product launch
    * Potential regulatory scrutiny on privacy and breach notification obligations
    * Customer trust degradation and possible legal/financial consequences

## Mitigation Strategies

### Immediate Actions
- Implement strict server-side authorization checks.
- Enforce authentication for all customer/order API endpoints.
- Notify potentially affected users and advise vigilance against phishing attempts.

### Engineering Controls
- Use indirect object references instead of predictable identifiers.
- Conduct secure code reviews and dedicated API penetration testing.
- Apply rate limiting and anomaly monitoring to detect enumeration behavior.
- Deploy Web Application Firewall (WAF) protections for abuse patterns.

### Assurance and Monitoring
- Perform independent third-party security assessments of ecommerce platforms.
- Establish ongoing API security testing in release pipelines.

## Resources and References

!!! info "Open-Source Reporting"
    - [Trump Mobile site leaks customer data as phone finally ships](https://www.theregister.com/security/2026/05/22/trump-mobile-site-leaks-customer-data-as-phone-finally-ships/5244828)
    - [Trump Mobile confirms it exposed customers' personal data, including phone numbers and home addresses | TechCrunch](https://techcrunch.com/2026/05/22/trump-mobile-confirms-it-exposed-customers-personal-data-including-phone-numbers-and-home-addresses/)
    - [Trump Mobile may be leaking customer addresses | The Verge](https://www.theverge.com/gadgets/934522/trump-mobile-may-be-leaking-customer-addresses)
    - [Trump Mobile investigating potential exposure of would-be customers' personal information | Donald Trump | The Guardian](https://www.theguardian.com/us-news/2026/may/23/trump-mobile-investigating-potential-exposure-of-would-be-customers-personal-information)
    - [Trump Mobile website loophole exposes customers' personal data - 'do not order unless you're ready for your information to be leaked' | Tom's Guide](https://www.tomsguide.com/phones/trump-mobile-website-loophole-exposes-customers-personal-data-do-not-order-unless-youre-ready-for-your-information-to-be-leaked)
    - [Trump Mobile's T1 phone arrives - finally](https://www.fierce-network.com/wireless/trump-mobiles-t1-phone-arrives-finally)

---

*Last Updated: May 24, 2026*
