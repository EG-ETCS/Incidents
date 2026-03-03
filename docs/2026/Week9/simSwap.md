# Dubai SIM-Swap Scam Exploiting Regional Tensions
![alt text](images/simSwap.png)

**SIM-Swap Fraud**{.cve-chip}  **Social Engineering**{.cve-chip}  **Identity Abuse**{.cve-chip}  **Crisis-Themed Scam**{.cve-chip}

## Overview
Scammers targeted Dubai residents by impersonating officials from a fictitious “Dubai Crisis Management” department falsely presented as linked to Dubai Police. Attackers sought sensitive personal and digital identity data that could later be used to perform SIM-swap fraud.

The activity was reported shortly after Iranian missile and drone activity affecting the UAE information environment. Threat actors appear to be exploiting fear and uncertainty during a regional crisis to increase social-engineering success.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Incident Type** | Social-engineering driven SIM-swap fraud campaign |
| **Target Region** | Dubai / UAE residents |
| **Primary Pretext** | Fake “Dubai Crisis Management” authority calls/messages |
| **Requested Data** | UAE Pass credentials, Emirates ID details |
| **Fraud Objective** | Socially engineer telecom operators to transfer victim number to attacker SIM |
| **Authentication Impact** | Interception of SMS OTP and 2FA verification codes |
| **Likely Follow-on Abuse** | Banking account access, identity theft, broader account takeover |

## Affected Products
- Mobile subscriber accounts vulnerable to SIM reassignment fraud
- UAE Pass / digital identity-linked services exposed through credential disclosure
- Banking and online services relying on SMS-based OTP/2FA
- Residents receiving unsolicited calls/messages from impersonated “official” actors
- Status: Active social-engineering risk; public warnings issued

## Technical Details

### Social Engineering Modus Operandi
- Attackers initiate unsolicited calls or messages while posing as crisis-management or police-linked authorities.
- Communication uses urgency and fear related to regional security developments.
- Victims are pressured to disclose identity and authentication-linked details.

### Data Abuse Path
- UAE Pass credentials and Emirates ID details are targeted as high-value identity signals.
- Collected data can be reused to pass operator verification checks.
- Attackers then attempt SIM transfer requests through carrier support channels.

### SIM-Swap Outcome
- Victim phone number is moved to attacker-controlled SIM.
- SMS-based OTP and verification messages are redirected to attacker device.
- Enables unauthorized access to financial and high-value digital services.

## Attack Scenario
1. **Reconnaissance**:
    - Threat actor acquires basic resident contact data (phone numbers and profiles).

2. **Pretexting Call/Message**:
    - Attacker impersonates crisis-response or law-enforcement authority.

3. **Credential/Identity Harvesting**:
    - Victim is convinced to share UAE Pass credentials and/or Emirates ID details.

4. **Carrier Social Engineering**:
    - Attacker submits fraudulent SIM transfer request using harvested identity data.

5. **Account Takeover and Monetization**:
    - Attacker intercepts OTP/2FA messages, accesses banking/services, and performs fraud.

## Impact Assessment

=== "Integrity"
    * Unauthorized modification of subscriber SIM ownership and account recovery channels
    * Fraudulent transactions and account setting changes in dependent services
    * Potential downstream identity misuse across linked digital platforms

=== "Confidentiality"
    * Exposure of personal identity data (UAE Pass / Emirates ID-linked details)
    * Interception of private SMS OTP and verification traffic
    * Elevated risk of further credential theft and account compromise

=== "Availability"
    * Victims may lose access to their mobile number and critical services temporarily
    * Service lockouts and account recovery disruption during active fraud response
    * Operational strain on telecom and financial support channels

## Mitigation Strategies

### Official Guidance (Dubai Authorities)
- Do not share personal, banking, or verification information with unknown callers/texts
- Authorities do not request confidential data or OTP codes by phone/SMS
- Report suspicious contacts through official channels such as `901` or Dubai eCrime platform
- Independently verify any claimed official communication via known official numbers/channels

### Account Security Hardening
- Request SIM-lock PIN controls with mobile carriers where available
- Prefer app-based authenticator 2FA instead of SMS-based 2FA when supported
- Set stricter recovery controls and account alerts on banking/critical services

### Awareness and Response
- Conduct user awareness messaging on crisis-themed social engineering tactics
- Train support teams to recognize SIM-swap indicators and escalation triggers
- Monitor for unusual SIM replacement requests and rapid post-swap account activity

## Resources and References

!!! info "Open-Source Reporting"
    - [Scammers target Dubai bank accounts amid Iran missile salvo • The Register](https://www.theregister.com/2026/03/02/dubai_iran_sim_swap/)
    - [Dubai Police Warn: Scammers Pretending to Be Officials…](https://www.inkl.com/news/dubai-police-warn-scammers-pretending-to-be-officials-are-targeting-your-uae-pass-and-emirates-id)
    - [From Fake Eid Alerts To UAE Pass Scams, Dubai Police Warn Residents Amid Regional Tensions | Curly Tales](https://curlytales.com/middle-east/ct-scoop/from-fake-eid-alerts-to-uae-pass-scams-dubai-police-warn-residents-amid-regional-tensions/)
    - [Dubai authorities warn of scams amid rising tensions in the Middle East](https://www.timeslive.co.za/news/2026-03-02-dubai-authorities-warn-of-scams-amid-rising-tensions-in-the-middle-east/)
    - [Dubai Police caution public on SIM fraud amid heightened alert amid US-Iran war: 'Attempts aim to...'](https://www.moneycontrol.com/news/trends/dubai-police-caution-public-on-sim-fraud-amid-heightened-alert-amid-us-iran-war-attempts-aim-to-13847956.html)
    - [شرطة دبي تحذر من محتالين ينتحلون صفة موظفي "إدارة الأزمات" للاستيلاء على بيانات الهوية الرقمية وبطاقة الهوية](https://www.emaratalyoum.com/local-section/accidents/2026-03-02-1.2020925)

---

*Last Updated: March 3, 2026* 
