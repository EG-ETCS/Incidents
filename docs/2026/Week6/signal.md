# Signal Account Hijacking Campaign

**Phishing**{.cve-chip}  **Account Takeover**{.cve-chip}  **Social Engineering**{.cve-chip}

## Overview
German domestic security (BfV) and cybersecurity (BSI) agencies warned of phishing attacks leveraging the Signal messaging app to compromise accounts by tricking victims into handing over PINs or scanning a QR code. The goal is to hijack accounts or link attackers’ devices to victims’ accounts, enabling access to private chats, contacts, and networks. The campaign relies on social engineering rather than malware or software vulnerabilities.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Threat Type** | Phishing / Social Engineering |
| **Target Platform** | Signal Messenger |
| **Exploit Method** | PIN/SMS code theft or QR code device linking |
| **User Interaction** | Required |
| **Malware** | None |
| **Persistence** | Linked device access |
| **Data Exposure** | Chats, contacts, group networks |

## Affected Products
- Signal Messenger users
- High-profile targets (politicians, military, journalists)
- Organizations using Signal for sensitive communications
- Status: Active campaign

## Technical Details

### Techniques
- **Fake support messages**: Attackers impersonate “Signal Support” or a “Signal Security ChatBot” to request PIN or SMS verification codes
- **QR-code trick**: Victims are convinced to scan a QR code that links their account to an attacker-controlled device, allowing access to recent messages (up to ~45 days)

![alt text](images/signal1.png)

![alt text](images/signal2.png)

### Attack Characteristics
- No malware or vulnerability exploitation
- Pure social engineering via in-app messaging
- Focused on credential and device-linking abuse

## Attack Scenario
1. Attacker sends a message within Signal, posing as support and claiming account issues
2. Target is urged to share verification codes or PINs
3. If the target complies, the attacker registers the account on their device
4. In the QR-code variant, the victim’s account is silently linked to the attacker’s device
5. Attacker gains ongoing access to chats, contacts, and group communications
6. Attacker can impersonate the victim to target their networks

## Impact Assessment

=== "Confidentiality"
    * Access to private chats and messages
    * Exposure of contact lists and group memberships
    * Intelligence gathering on sensitive communications

=== "Integrity"
    * Impersonation of victims in chats and groups
    * Manipulation of communications to spread disinformation
    * Abuse of trusted relationships in professional networks

=== "Availability"
    * Loss of account control and messaging access
    * Potential lockout of legitimate user
    * Disruption of secure communications channels

## Mitigation Strategies

### Immediate Actions
- Do NOT respond to unsolicited “support” messages in Signal
- Never share your Signal PIN or SMS verification codes
- Enable Registration Lock to require a PIN when registering new devices
- Review linked devices and remove unknown ones immediately

### Short-term Measures
- Only scan QR codes you initiate yourself
- Educate users on social engineering tactics targeting Signal
- Encourage use of strong, unique PINs for Registration Lock
- Report suspected compromise to authorities or security teams

### Monitoring & Detection
- Regularly review linked devices in Signal settings
- Monitor for unexpected new device link notifications
- Watch for unusual account behavior or messages sent by attacker

### Long-term Solutions
- Implement security awareness training for high-risk groups
- Use alternative secure channels for sensitive coordination
- Establish incident response playbooks for account takeover
- Advocate for phishing-resistant verification methods

## Resources and References

!!! info "Incident Reports"
    - [German Agencies Warn of Signal Phishing Targeting Politicians, Military, Journalists](https://thehackernews.com/2026/02/german-agencies-warn-of-signal-phishing.html)
    - [State-backed phishing attacks targeting military officials and journalists on Signal - Help Net Security](https://www.helpnetsecurity.com/2026/02/06/state-linked-phishing-europe-journalists-signal/)
    - [Germany warns of Signal account attacks targeting high-profile figures](https://cyberinsider.com/germany-warns-of-signal-account-attacks-targeting-high-profile-figures/)
    - [Signal Under Siege: How Russian-Linked Hackers Are Exploiting the Encrypted Messenger's Trust to Infiltrate High-Value Targets](https://www.webpronews.com/signal-under-siege-how-russian-linked-hackers-are-exploiting-the-encrypted-messengers-trust-to-infiltrate-high-value-targets/)

---

*Last Updated: February 8, 2026* 
