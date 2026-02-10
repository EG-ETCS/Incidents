# CISA Warning: Spyware Campaigns Targeting Messaging App Users
![Spyware campaign](images/spyware.png)

**Commercial Spyware**{.cve-chip}  
**Zero-Click Exploits**{.cve-chip}  
**Messaging Apps Targeted**{.cve-chip}

## Overview
CISA warns that multiple cyber-threat actors are actively leveraging commercial spyware to target users of mobile messaging applications (e.g., WhatsApp, Signal). They use advanced methods — social engineering, zero-click exploits, impersonation — to deliver spyware and gain unauthorized access to victims' messaging apps and devices, then deploy additional malicious payloads.

![](images/spyware1.png)
## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Threat Type** | Commercial Spyware Campaigns |
| **Target Applications** | WhatsApp, Signal, Telegram, ToTok |
| **Attack Vector** | Social engineering, zero-click exploits, malicious QR codes |
| **Affected Platforms** | iOS, Android |
| **Known Vulnerabilities** | CVE-2025-55177, CVE-2025-43300, CVE-2025-21042 |

### Attack Methods

#### 1. Malicious Device-Linking QR Codes
- Abuse "linked devices" features (e.g., in Signal and WhatsApp)
- Silently add attacker-controlled devices to a victim's account

#### 2. Zero-Click Exploits
- Delivered through messaging apps (e.g., crafted images over WhatsApp)
- Trigger vulnerabilities in mobile OS without user interaction

#### 3. Trojanized or Spoofed Apps
- **ProSpy** and **ToSpy** masquerading as Signal
- **ClayRat** distributed via fake Telegram/WhatsApp/Google/TikTok apps
- Fake ToTok and other popular messaging apps

### Specific Known Vulnerabilities Exploited

#### iOS/macOS (WhatsApp)
- **CVE-2025-55177**: Zero-click bug patched by WhatsApp in August 2025
- **CVE-2025-43300**: OS / image-parsing flaw
- Chained together to deliver spyware

#### Android (LANDFALL Campaign)
- Malicious image (e.g., a malformed .DNG image) delivered over WhatsApp
- Exploits Samsung/Android image-codec vulnerability (**CVE-2025-21042** / similar)
- Triggers memory-based payload extraction & remote code execution
- All without requiring the user to open the image

### Spyware Capabilities
Once spyware is on device, it can:
- Access messages, contact list, files
- Record or exfiltrate data
- Monitor microphone/camera
- Track location
- Give persistent access
- Deliver further malware

## Attack Scenario

1. **Target Profiling**: The attacker profiles high-value targets who use Signal or WhatsApp on Android or iOS.

2. **Delivery**: The victim receives a phishing message, link, or QR code that appears to be for account verification, device linking, or an "upgrade" of their messaging app.

3. **Exploitation**: When the victim scans the QR code or installs the fake app, the attacker either:
   - Adds an attacker-controlled device to the victim's messaging account via the linked-device feature
   - Exploits a zero-click or app/OS vulnerability to silently install spyware/RAT on the device

4. **Data Exfiltration**: The spyware exfiltrates messages, contact lists, files, and metadata, and may enable microphone/camera access and other surveillance capabilities.

5. **Persistent Access**: The attacker uses this persistent access for espionage, monitoring of communications, or follow-on operations against the victim's organization.

## Impact Assessment

=== "Confidentiality"
    * Loss of confidentiality of supposedly end-to-end encrypted messages (read at endpoint)
    * Exposure of sensitive data: contacts, call logs, files, location data, and device identifiers

=== "Surveillance"
    * Full-device surveillance, including microphone and camera activation
    * Location tracking
    * Strategic intelligence collection against governments, militaries, political actors, and civil-society groups

=== "Organizational Risk"
    * Severe risks to sensitive negotiations
    * Operations security compromised
    * Safety of activists or officials whose communications are monitored
    * Potential policy, diplomatic, and safety implications

## Mitigations

### 📱 Keep Systems Updated
- Keep OS and messaging apps up to date
- Apply security patches promptly (especially for known exploited vulnerabilities)

### 🔒 Security Settings
- **Disable "automatic media preview"** / auto-download of attachments in messaging apps to reduce zero-click or malicious-image risk
- **Review "linked devices"** / device-linking sessions regularly
- Remove unfamiliar linked sessions
- Disable or monitor multi-device login when possible

### 🛡️ App Security
- Avoid installing apps or "plugins" from untrusted sources
- Only use official app stores
- Distrust unexpected "update prompts"

### 🎯 For High-Value Targets
- Consider using a **dedicated hardened device** for sensitive communications
- Separate (less-sensitive) devices for general use ("compartmentalization")

### 🔐 Authentication & Access Control
- Use **strong authentication practices**
- Avoid SMS-based MFA
- Prefer phishing-resistant authentication
- Use password managers
- Set security PINs with telecom providers

### 🛠️ Platform Protections
- **iOS**: Enable Lockdown Mode, iCloud Private Relay
- **Android**: Enable Google Play Protect, enhanced Safe Browsing, and minimal app permissions

## Resources & References

!!! info "CISA Alerts & Media Coverage"
    * [CISA Warns of Active Spyware Campaigns Hijacking High-Value Signal and WhatsApp Users](https://thehackernews.com/2025/11/cisa-warns-of-active-spyware-campaigns.html)
    * [CISA urges mobile security as it warns of sophisticated spyware attacks | Cybersecurity Dive](https://www.cybersecuritydive.com/news/cisa-spyware-alert-messaging-apps-security-warning/806429/)
    * [CISA Warns of Spyware Targeting Messaging App Users - SecurityWeek](https://www.securityweek.com/cisa-warns-of-spyware-targeting-messaging-app-users/)
    * [WhatsApp fixes 'zero-click' bug used to hack Apple users with spyware | TechCrunch](https://techcrunch.com/2025/08/29/whatsapp-fixes-zero-click-bug-used-to-hack-apple-users-with-spyware/)
    * [CISA Emergency Alert: Commercial Spyware Exploiting Zero-Click and Malicious QR Codes](https://securityonline.info/cisa-emergency-alert-commercial-spyware-exploiting-zero-click-and-malicious-qr-codes-to-hijack-messaging-apps/)
    * [CISA: Spyware crews breaking into Signal, WhatsApp accounts • The Register](https://www.theregister.com/2025/11/25/cisa_spyware_gangs)
    * [Spyware Allows Cyber Threat Actors to Target Users of Messaging Applications](https://news247wp.com/2025/11/25/spyware-allows-cyber-threat-actors-to-target-users-of-messaging-applications/)
    * [Hackers target WhatsApp, Signal apps with spyware | Cybernews](https://cybernews.com/security/cisa-warning-messaging-apps-deliver-zero-click-spyware-personal-devices-high-profile/)