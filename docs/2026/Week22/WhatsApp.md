# Zero-Click WhatsApp Account Takeover Targeting iOS 16 Devices
![alt text](images/WhatsApp.png)

**CVE-2025-43300**{.cve-chip} **CVE-2025-55177**{.cve-chip} **Zero-Click Exploit**{.cve-chip} **WhatsApp**{.cve-chip} **iOS**{.cve-chip}

## Overview

Security researchers disclosed a sophisticated zero-click attack chain capable of hijacking WhatsApp accounts on iPhones running iOS 16 without any user interaction — no QR-code scanning, no linked-device approval, and no visible notification to the victim. The attack chains two vulnerabilities: **CVE-2025-43300** (Apple ImageIO memory corruption) and **CVE-2025-55177** (WhatsApp linked-device synchronization and authorization weakness). Attackers can obtain or generate authentication artifacts to establish a rogue WhatsApp session that may not appear in the victim's Linked Devices list. Victims typically only notice the compromise after being unexpectedly logged out of WhatsApp. The attack is particularly relevant against high-value targets such as journalists, executives, and government officials.

![alt text](images/WhatsApp1.png)

## Technical Specifications

| Attribute | Details |
|---|---|
| **CVE-1** | CVE-2025-43300 — Apple ImageIO memory corruption vulnerability |
| **CVE-2** | CVE-2025-55177 — WhatsApp linked-device synchronization and authorization weakness |
| **Attack Type** | Zero-click — no user interaction required |
| **Affected Platform** | iPhones running iOS 16 (vulnerable versions) |
| **Delivery Vector** | Specially crafted WhatsApp message or synchronization payload |
| **Exploit Outcome** | Authentication/session artifact extraction → rogue WhatsApp session established |
| **Detection Evasion** | Malicious session may not appear in victim's Linked Devices list |
| **Victim Indicator** | Unexpected WhatsApp logout may be the only visible sign |
| **High-Risk Targets** | Journalists, executives, government officials, activists |

## Affected Products

- **WhatsApp** on iPhones running vulnerable iOS 16 versions (prior to patches for CVE-2025-43300 and CVE-2025-55177)
- **Apple iOS 16** — specifically versions containing the ImageIO memory corruption flaw (CVE-2025-43300)

## Attack Scenario

1. Threat actor identifies a target using a vulnerable iPhone running an unpatched version of iOS 16 with WhatsApp installed
2. A maliciously crafted WhatsApp message or synchronization payload is sent to the victim's WhatsApp number — no action by the victim is required to trigger the exploit
3. The payload triggers CVE-2025-43300 (Apple ImageIO memory corruption) as the message is processed, providing a memory-level foothold within the device
4. The exploit chain leverages CVE-2025-55177 (WhatsApp linked-device synchronization weakness) to extract or generate the authentication artifacts needed to establish a new WhatsApp session
5. A rogue WhatsApp session is silently registered under the attacker's control; due to the authorization weakness, this session may not surface in the victim's Linked Devices list, bypassing the primary user-facing security indicator
6. The attacker gains real-time access to the victim's WhatsApp messages, contacts, and active conversations while remaining undetected through standard monitoring
7. The compromised account is exploited for espionage, impersonation, financial fraud against contacts, or as a launchpad for further social-engineering attacks — the victim may only discover the breach when unexpectedly logged out of WhatsApp

## Impact

=== "Account and Privacy Impact"

    - Unauthorized access to all WhatsApp messages, media, contacts, and conversation history without the victim's knowledge
    - Exposure of private, sensitive, or confidential communications in both individual and group chats
    - Impersonation of the victim in ongoing conversations, enabling social-engineering attacks against their contacts
    - Loss of trust in the integrity of WhatsApp as a secure communication channel

=== "Fraud and Espionage Risk"

    - Financial fraud targeting the victim's contacts using their identity and conversation context
    - Espionage against journalists, executives, government officials, and activists — consistent with the profile of targets historically subject to mobile zero-click attacks
    - Real-time intelligence access to ongoing sensitive discussions, deal negotiations, or operational communications

=== "Detection and Response Challenges"

    - The rogue session may not appear in the victim's Linked Devices list, removing the primary user-visible indicator of unauthorized access
    - Zero-click delivery means no suspicious user action (clicking a link, scanning a QR code) precedes the compromise — standard security awareness training does not mitigate the risk
    - Victims often only discover the breach after an unexpected logout, by which point significant message history may have been accessed or exfiltrated

## Mitigations

### Immediate Patching

- **Update WhatsApp to the latest available version** — ensure the fix for CVE-2025-55177 is applied; WhatsApp updates are delivered via the App Store and can be forced through Settings > General > Software Update
- **Upgrade to the latest supported iOS release** — apply the Apple patch addressing CVE-2025-43300 (ImageIO memory corruption); iOS updates are the primary mitigation for the kernel/framework-level component of the exploit chain

### High-Risk Users

- **Enable Lockdown Mode** on iPhones for journalists, executives, government officials, activists, and others at elevated risk of targeted mobile attacks; Lockdown Mode restricts the attack surface available to zero-click and zero-day exploit chains
- **Conduct mobile device forensic analysis** if compromise is suspected — unexpected WhatsApp logout, unfamiliar linked devices, or anomalous account behavior warrant immediate investigation using mobile forensic tooling

### Ongoing Monitoring and Hygiene

- **Monitor for unexpected WhatsApp logouts** or unrecognized active sessions as a potential post-compromise indicator
- **Review Linked Devices in WhatsApp Settings** regularly (`Settings > Linked Devices`) and revoke any sessions you do not recognize; while the exploit may suppress this entry, the check should still be performed
- **Enable strong device security protections** — Face ID, Touch ID, and a strong passcode limit physical access risk and reduce the value of device-level exploitation
- **Apply security updates immediately** when released by Apple and WhatsApp, especially during periods when zero-click mobile vulnerabilities are being actively disclosed or exploited

## Resources

!!! info "Open-Source Reporting"
    - [Zero-Click WhatsApp Account Takeover Hits iPhone Users Running iOS 16. No Linked Devices, No Warning](https://securityaffairs.com/192627/security/zero-click-whatsapp-account-takeover-hits-iphone-users-running-ios-16-no-linked-devices-no-warning.html)
    - [Zero Click WhatsApp Takeover Hits iOS 16 iPhone Users](https://www.gblock.app/articles/whatsapp-zero-click-account-takeover-ios-16-may-2026)
    - [Zero-Click Attack Hijacks WhatsApp Accounts on iOS 16 — SC Media](https://www.scworld.com/brief/zero-click-attack-hijacks-whatsapp-accounts-on-ios-16)

---

*Last Updated: June 1, 2026*