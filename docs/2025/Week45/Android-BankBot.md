# Android/BankBot-YNRK Malware
![Android BankBot](images/android-bankbot.png)

**Advanced Android banking trojan**{.cve-chip}
**Credential and fund theft**{.cve-chip}
**Accessibility abuse**{.cve-chip}

## Overview
Android/BankBot-YNRK is a sophisticated Android banking trojan disguised as the Indonesian government’s “Identitas Kependudukan Digital” (Digital ID) app. It automates theft of credentials and funds from banking and crypto apps using accessibility abuse, environment detection, persistent C2, and advanced social engineering.

## Technical Details

- Three related APK samples written in Kotlin, using anti-emulation and device fingerprinting (manufacturer strings, screen resolutions)
- Accessibility Service exploitation enables granular device/UI control and automation
- Persistence through JobScheduler (30s intervals, persisted jobs) and Device Admin privileges
- Suppresses notification/audio streams to hide theft
- Uses C2 at ping[.]ynrkone[.]top:8181 in a “chat room” model
- Dynamic disguise as Google News app
- Direct targeting of bank and crypto wallet apps (MetaMask, Trust Wallet, Coin98, Exodus)

## Attack Scenario
1. Victim installs a fake app posing as a legitimate government service
2. App uses C2 (OPEN_ACCESSIBILITY) to prompt and obtain Accessibility privilege
3. Malware gains full UI control, opens banking/crypto apps, grabs sensitive data, automates unauthorized transactions
4. Maintains stealth by muting notifications and adopting legitimate app appearance
5. Persistent C2 connection for continual attacker commands

## Impact Assessment

- Loss of banking and crypto credentials and funds
- Undetected unauthorized financial transactions
- Persistent remote access
- Privacy/data breaches for individuals and potentially for enterprise networks
- Regulatory risk due to mass credential exfiltration

## Mitigation Strategies

- Avoid sideloading apps/APKs; only use official app stores
- Disable unknown source installs
- Strictly review/revoke Accessibility and Device Admin permissions
- Monitor/block related C2 domains (ping.ynrkone.top, plp.*)
- Employ EDR/mobile threat defense for detection
- User awareness campaigns on Accessibility risks
- Patch Android to latest OS/security level (Android 14+ offers additional mitigations)

## Resources

1. [Investigation Report: Android/BankBot-YNRK Mobile Banking Trojan - Live Threat Intelligence - Threat Radar | OffSeq.com](https://offseq.com)
2. [Investigation Report: Android/BankBot-YNRK Mobile Banking Trojan - CYFIRMA](https://cyfirma.com)
3. [Next-Gen Android Banking Trojan Hides in Digital ID App, Automates Crypto Wallet Theft and Evades Emulators](https://securityaffairs.com/)
