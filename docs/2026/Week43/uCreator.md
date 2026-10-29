# uCreator Android Spyware (YingGai)
![alt text](images/uCreator.png)

**uCreator (YingGai)**{.cve-chip} **Android Spyware**{.cve-chip} **Telegram Targeting**{.cve-chip} **WeChat Cloning**{.cve-chip} **Virtualization Abuse**{.cve-chip}

## Overview

uCreator, also known as YingGai, is a commercially available Android spyware platform targeting messaging applications and potentially mobile-wallet workflows.

Researchers reported that it can operate through modified copies of legitimate apps or a malicious container application called Onion Box. Reported capabilities include theft of Telegram two-step verification passwords, chat-data access, account-session manipulation, and WeChat account cloning.

## Technical Details

- Uses application virtualization and runtime code-hooking techniques, including VirtualApp, LSPatch, and Pine.
- Can embed malicious components in modified Telegram and Telegram X applications.
- Intercepts Telegram two-step verification passwords before they are hashed by the application.
- Can access message-store data and manipulate account authorization sessions.
- Uses an application container to run WeChat and extract account identity information.
- Supports remote command execution within the spyware application environment and communicates with command-and-control infrastructure.
- Some malicious components are downloaded after installation, potentially making static analysis of the initial APK insufficient.
- The Telegram component shares technical indicators with the Baohuo Android backdoor reported by Doctor Web.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Threat Name** | uCreator (YingGai) |
| **Platform** | Android |
| **Primary Targets** | Messaging apps (notably Telegram and WeChat), potentially wallet-related data |
| **Core Techniques** | App virtualization, runtime hooking, modified APK delivery |
| **Mentioned Tooling** | VirtualApp, LSPatch, Pine, Onion Box container |
| **Credential Risk** | Telegram 2FA password interception prior to app-side hashing |
| **Post-Install Behavior** | Dynamic component download and remote tasking via C2 |
| **Related Indicator Context** | Overlap with Baohuo-related Telegram component indicators |

## Affected Products

- Modified Telegram and Telegram X APK variants distributed outside trusted channels.
- WeChat instances executed through malicious Onion Box container workflows.
- Android devices where sideloading or untrusted app installation paths are used.

## Attack Scenario

1. An attacker distributes modified Telegram or Telegram X APKs via unofficial sites, third-party stores, or social engineering.
2. Alternatively, a victim runs WeChat through the malicious Onion Box container.
3. The victim installs or launches the app and signs in.
4. Malicious components execute in-app, intercept authentication data, and access available account/session information.
5. Collected data is sent to attacker-controlled infrastructure.
6. Attackers may use stolen credentials or session data to manipulate accounts, access private communications, or clone WeChat identities.

This scenario reflects reported capabilities and is not necessarily the exact sequence for every infection.

## Impact Assessment

=== "Account and Privacy Impact"

    - Theft of Telegram two-step verification passwords and other sensitive account information
    - Unauthorized access to private messages, contacts, and profile data

=== "Operational and Abuse Impact"

    - Potential account takeover, session manipulation, or account lockout
    - WeChat account cloning and user impersonation risk

=== "Financial and Follow-On Risk"

    - Potential fraud where wallet or authentication-related data is exposed
    - Increased social-engineering risk using stolen contacts and account identities

## Mitigation Strategies

1. Install messaging apps only from official, trusted distribution sources.
2. Avoid sideloading APKs from unknown websites or unsolicited links.
3. Enable Google Play Protect and keep Android OS/apps updated.
4. Verify developer identity and app signatures; package names alone are insufficient.
5. Review Telegram active sessions and terminate unfamiliar sessions from a trusted device.
6. Enable Telegram two-step verification and secure its recovery email.
7. Investigate suspicious artifacts including TgJarPine.dex with package signatures, hashes, and network indicators.

## Resources and References

!!! info "Public Reporting"
    1. [uCreator Android Spyware Can Steal Telegram 2FA Passwords and Clone WeChat Accounts](https://thehackernews.com/2026/10/ucreator-android-spyware-can-steal.html)
    2. [Researchers Uncover Rentable Android Spyware uCreater Targeting WeChat and Telegram](https://securityaffairs.com/201764/malware/researchers-uncover-rentable-android-spyware-ucreater-targeting-wechat-and-telegram.html)
    3. [uCreator: virtualization-based Android spyware platform targeting WeChat, Telegram and other messaging apps](https://www.0x0v1.com/ucreator-virtualization-based-android-spyware-platform-targeting-wechat-telegram-and-other-messaging-apps/)

---

*Last Updated: October 29, 2026*
