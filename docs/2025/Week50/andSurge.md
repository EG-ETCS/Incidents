# Android Malware Surge: FvncBot, SeedSnatcher, and Upgraded ClayRat

**Banking Trojan**{.cve-chip}  
**Cryptocurrency Stealer**{.cve-chip}  
**Spyware**{.cve-chip}

## Overview

Three major Android malware strains were identified circulating globally:

**FvncBot** – A banking trojan posing as a Polish mBank security app; abuses Accessibility Services to steal credentials and enables hidden VNC-style remote control for fraudulent banking transactions.

**SeedSnatcher** – A targeted cryptocurrency stealer distributed via Telegram, designed to harvest wallet seed phrases, intercept SMS (OTP/2FA), and exfiltrate device data to a remote C2.

**Upgraded ClayRat** – A new, more powerful variant of known spyware; capable of keystroke logging, screen recording, overlay attacks, device unlocking, and persistent phishing notifications.

Together, these threats represent an **advanced escalation in Android malware capabilities** involving remote control, phishing overlays, SMS interception, and full device compromise.

---

## Incident Classification

| **Attribute** | **Details** |
|---------------|-------------|
| **Incident Type** | Banking Trojan, Cryptocurrency Theft, Mobile Spyware Campaign |
| **Affected Country / Region** | Global (Poland-targeted for FvncBot, cryptocurrency users worldwide for SeedSnatcher) |
| **Targeted Sector** | Financial Services, Cryptocurrency Users, General Mobile Users |
| **Criticality** | **High** — Full device compromise, financial theft, remote control, SMS/OTP interception, credential harvesting |

---

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Malware Families** | FvncBot (Banking Trojan), SeedSnatcher (Crypto Stealer), ClayRat (Spyware) |
| **Target Platform** | Android |
| **Distribution Method** | Phishing links, Telegram, fake app websites, APK sideloading |
| **Primary Capabilities** | Remote control, credential theft, SMS interception, overlay attacks, keylogging |

### FvncBot

#### Impersonation
- Impersonates **mBank (Poland)**
- Poses as a security or banking update app

#### Permissions Abuse
- Requests **Accessibility Services** → grants full control

#### Capabilities
- **Phishing overlays** on banking apps
- **Keylogging and screen capture**
- **Hidden VNC (HVNC)** remote device control
- **Automated fraud** (taps/swipes/filling forms)
- C2 supports remote scripts and automated banking operations

![](images/andSurge1.png)

### SeedSnatcher

#### Distribution
- Distributed as an app called **"Coin"**
- Package: `com.pureabuladon.auxes`
- Primarily via **Telegram**

#### Stolen Data
- **Crypto seed phrases, wallet recovery mnemonics**
- **SMS messages** (OTP/2FA codes)
- Contacts, files, logs

#### Exfiltration
- Exfiltrates data to **cloud infrastructure**

### Upgraded ClayRat

#### Full Spyware Toolkit
- **Keylogging**
- **Screen recording**
- **Overlay attacks**
- **Fake notifications**
- Ability to **bypass PIN/pattern**

#### Delivery Method
- Delivered via **phishing websites** impersonating known apps:
  - "YouTube Pro"
  - Taxi apps
  - Other popular applications

![](images/andSurge3.png)

#### Persistence
- Strong persistence using overlays and notification hijacking

![](images/andSurge2.png)

---

## Attack Scenario

1. **Initial Contact**: Victim receives a phishing link, Telegram message, or fake app website.

2. **Download**: They download an APK claiming to be:
    - A bank/security update
    - Wallet tool
    - Utility app

3. **Permission Requests**: The malware requests:
    - **Accessibility Services**
    - **Overlay permissions**
    - **SMS permissions**

4. **Post-Installation Activities**: Once granted, the malware:
    - Steals credentials or wallet seeds
    - Intercepts SMS/OTP
    - Monitors screen content
    - Displays phishing overlays
    - Takes **remote control of the device (HVNC)**

5. **Attacker Actions**: Attackers use stolen credentials or remote access to:
    - Empty bank accounts
    - Transfer cryptocurrency
    - Take over online accounts
    - Lock the user out of the device or apps

---

## Impact Assessment

=== "Financial Theft"
    * **Unauthorized bank transfers**
    * **Cryptocurrency asset draining**
    * Direct financial loss to victims

=== "Account Takeover"
    * **Banking accounts** compromised
    * **Email, social media** access stolen
    * **Wallet applications** hijacked

=== "Device Compromise"
    * **Full remote control** via HVNC
    * **Persistent spyware** installation
    * Device becomes attacker-controlled

=== "Privacy Violation"
    * **Exfiltration of personal data**
    * Messages, contacts stolen
    * Complete loss of privacy

=== "Bypass of Security Controls"
    * **OTP interception**
    * **Overlay phishing**
    * **PIN unlock bypass**
    * Traditional security measures rendered ineffective

=== "Global Exposure"
    * **High-risk global exposure**
    * Malware is generalizable for any region or bank
    * Not limited to specific geography

---

## Mitigations

### 👤 For Individuals

#### App Installation
- Install apps **ONLY from trusted app stores** (Google Play Store)
- **Avoid sideloading APKs** from Telegram/WhatsApp/unknown links

#### Permissions
- **Do not grant Accessibility Services** unless absolutely necessary
- Disable **"Install unknown apps"** for messaging apps
- Review and revoke unnecessary app permissions

#### Security Tools
- Use **reputable mobile security/antivirus solutions**
- Enable **Google Play Protect**

#### Monitoring
- **Monitor bank accounts** and crypto wallets for suspicious activity
- Set up transaction alerts

#### Cryptocurrency Security
- Consider using **hardware wallets** for cryptocurrency
- Never share seed phrases or recovery mnemonics

### 🏢 For Organizations

#### Mobile Threat Detection
- Enable **mobile threat detection (MTD)** solutions
- Monitor for anomalous mobile device behavior via **EDR/MDM**

#### User Education
- **Educate users** on phishing and APK risks
- Regular security awareness training

#### Detection & Policy
- Detect suspicious apps requesting **overlay or Accessibility permissions**
- **Enforce policy restricting sideloading** on corporate devices

#### Device Management
- Use **Mobile Device Management (MDM)** solutions
- Enforce security policies on corporate mobile devices

### 🏦 For Banks / Crypto Platforms

#### Fraud Detection
- Implement **behavioral fraud detection** for HVNC-like activity
- Monitor for automated/robotic interactions typical of malware

#### Authentication
- Use **strong transaction verification** separate from SMS/OTP
- Implement **hardware token authentication** where possible

#### Monitoring
- Monitor for:
    - Rapid consecutive transactions
    - Unusual device fingerprints
    - VNC-like control patterns

---

## Resources & References

!!! info "Research & Analysis"
    * [Android Malware FvncBot, SeedSnatcher, and ClayRat Gain Stronger Data Theft Features](https://thehackernews.com/2025/12/android-malware-fvncbot-seedsnatcher.html)
    * [New Android Malware Threats: FvncBot, SeedSnatcher, and ClayRat Escalate Data Theft Tactics](https://www.betterworldtechnology.com/post/new-android-malware-threats-fvncbot-seedsnatcher-and-clayrat-escalate-data-theft-tactics)
    * [New Android Malware Surge: FvncBot, SeedSnatcher, and an Upgraded ClayRat Expand Mobile Threat Landscape](https://www.thecybersyrup.com/p/new-android-malware-surge-fvncbot-seedsnatcher-and-an-upgraded-clayrat-expand-mobile-threat-landscap)
    * [TrojanSpy:AndroidOS/SeedSnatcher!AMTB threat description - Microsoft Security Intelligence](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=TrojanSpy:AndroidOS%2FSeedSnatcher!AMTB&ThreatID=2147958806)
    * ["Sneaky" new Android malware takes over your phone, hiding in fake news and ID apps | Malwarebytes](https://www.malwarebytes.com/blog/news/2025/11/sneaky-new-android-malware-takes-over-your-phone-hiding-in-fake-news-and-id-apps)
    * [Return of ClayRat: Expanded Features and Techniques](https://zimperium.com/blog/return-of-clayrat-expanded-features-and-techniques)

!!! warning "High Priority Threat"
    These malware families represent a **significant escalation** in Android mobile threats, combining:
    - Remote control capabilities
    - Financial theft mechanisms
    - Cryptocurrency targeting
    - SMS/OTP interception
    
    Users should exercise **extreme caution** when installing any apps outside official app stores.

!!! danger "SeedSnatcher Package Identifier"
    ```
    Package: com.pureabuladon.auxes
    App Name: "Coin"
    ```
    
    If you have installed any app with this package name, **immediately**:
    
        1. Uninstall the app
        2. Change all passwords
        3. Transfer cryptocurrency to new wallets with new seed phrases
        4. Contact your bank