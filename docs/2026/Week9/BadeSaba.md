# BadeSaba Calendar App Hack (Iranian Prayer-App Compromise)
![alt text](images/BadeSaba.png)

**Mobile App Compromise**{.cve-chip}  **Push Notification Abuse**{.cve-chip}  **Information Operations**{.cve-chip}  **Crisis-Time Targeting**{.cve-chip}

## Overview
The BadeSaba Calendar app, a widely used Iranian prayer-timing application with reportedly more than five million downloads, was reportedly compromised to send unauthorized push notifications to users. Messages in Persian urged members of Iranian security forces to defect or lay down weapons during an active military period and major domestic internet disruptions.

Based on open-source reporting, the incident appears to involve compromise of push-notification infrastructure rather than a user-device exploit chain. Responsibility remains unverified in independent public reporting.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Incident Type** | Mobile app backend compromise / unauthorized push broadcast |
| **Target Platform** | BadeSaba Calendar app ecosystem |
| **Primary Mechanism** | Abuse of push notification backend/control plane |
| **Access Path (Likely)** | Unauthorized access to cloud APIs, keys, or developer notification consoles |
| **User Interaction Required** | None (push notifications delivered passively) |
| **Observed Message Theme** | Persian-language defection/surrender prompts during conflict period |
| **Attribution Status** | No official confirmed claim; external attribution remains unverified |
| **Campaign Timing** | Coincided with reported airstrikes and broad internet disruptions |

## Affected Products
- BadeSaba Calendar mobile application users
- Push notification delivery infrastructure and related cloud control systems
- Users receiving emergency/prayer reminder notifications via the app ecosystem
- Status: Reported compromise event with trust and platform-integrity impact

## Technical Details

### Attack Vector
- Attackers reportedly compromised infrastructure used to manage or transmit app push notifications.
- This allowed large-scale message broadcast without requiring end-user interaction.

### Likely Abuse Points
- Cloud-based push APIs and service credentials
- Developer/admin control panels for notification campaigns
- Keys/tokens used to authorize mass notification delivery

### Operational Characteristics
- Messages were delivered in Persian and aligned with conflict-era narrative content.
- Delivery timing reportedly coincided with physical operations and major internet outages.
- Synchronization with broader disruption increased information-environment impact.

### Attribution Caveat
- Public reporting frequently suggests state-linked motivation based on timing and message theme.
- No independently verified, official attribution is confirmed in provided sources.

## Attack Scenario
1. **Pre-Positioning**:
    - Threat actor obtains unauthorized access to the BadeSaba push-notification backend ecosystem.

2. **Trigger Timing**:
    - During active military operations, actor initiates mass push campaigns.

3. **Payload Delivery**:
    - Users expecting routine prayer/calendar reminders receive political-military messages instead.

4. **Amplified Effect**:
    - Concurrent internet disruption reduces alternate verification channels.

5. **Trust Degradation**:
    - Users and operators lose confidence in app integrity and notification authenticity.

## Impact Assessment

=== "Mass Exposure & User Trust"
    * Millions of users potentially received unsolicited crisis-time messaging
    * Reduced trust in app notifications and digital public-information channels
    * Increased uncertainty around legitimacy of urgent mobile alerts

=== "Psychological & Information Operations"
    * Messaging may influence morale perceptions among civilians and security communities
    * Narrative injection during conflict can amplify confusion and pressure
    * App ecosystem becomes a vector for strategic psychological effects

=== "Security & Platform Risk"
    * Demonstrates weaponization potential of push-notification control planes
    * Highlights weak points in app backend/API credential governance
    * Reveals hybrid-warfare value of compromising high-reach mobile platforms

## Mitigation Strategies

### For Users and Platforms
- Cross-check high-impact push messages with official channels before acting
- Keep mobile apps updated from trusted stores only
- Treat crisis-time notifications as potentially manipulated until verified

### For Developers and Operators
- Harden push backend APIs, admin consoles, and cloud IAM controls
- Enforce MFA, least privilege, audit logging, and routine key/secret rotation
- Implement segmented authorization for high-volume broadcast actions

### Monitoring and Response
- Monitor for abnormal push volume/content/timing patterns
- Define automated thresholds and alerting for anomalous notification campaigns

## Resources and References

!!! info "Open-Source Reporting"
    - [Iran-Israel conflict: Iranian prayer app 'BadeSaba' with five million users hacked by Israel, report - Technology News | The Financial Express](https://www.financialexpress.com/life/technology-iranian-prayer-app-badesaba-with-five-million-users-hacked-by-israel-report-4160125/)
    - [Hackers Hit Iranian Apps and Websites: Iranians receives 'Defend your brothers, Time for ...' and other notifications from BadeSaba as Iranian apps and websites hit by hackers | - The Times of India](https://timesofindia.indiatimes.com/technology/tech-news/iranians-receives-defend-your-brothers-time-for-and-other-notifications-from-badesaba-as-iranian-apps-and-websites-hit-by-hackers/articleshow/128936110.cms)
    - [Iran Israel Live Updates Tehran Ayatollah Khamenei Mossad Trump: Israel Hacked Iranian Prayer App, Urged IRGC To Betray The Regime: Report](https://www.ndtv.com/world-news/iran-israel-live-updates-tehran-ayatollah-khamenei-mossad-trump-israel-hacked-iranian-prayer-app-urged-irgc-to-betray-the-regime-report-11155098)
    - ['Patriots, keep protesting': Iranian prayer app with five million users hacked by Israel, says report | World News - The Times of India](https://timesofindia.indiatimes.com/world/middle-east/patriots-keep-protesting-iranian-prayer-app-with-five-million-users-hacked-by-israel-says-report/articleshow/128921323.cms)
    - [Digital Warfare at 30,000 Feet: How Israel Hijacked an Iranian Prayer App to Broadcast Surrender Messages During Airstrikes](https://www.webpronews.com/digital-warfare-at-30000-feet-how-israel-hijacked-an-iranian-prayer-app-to-broadcast-surrender-messages-during-airstrikes/)
    - [Israel hacks prayer app to push propaganda to Iran: report • The Register](https://www.theregister.com/2026/03/02/iran_prayer_app_propaganda_hack_israel/)
    - [Popular Iranian App BadeSaba was Hacked to Send “Help Is on the Way” Alerts](https://hackread.com/popular-iranian-app-badesaba-hacked-alerts/)
    - [How the BadeSaba Prayer App Was Hacked in Iran and How to Protect Yourself](https://www.techloy.com/how-the-badesaba-prayer-app-was-hacked-in-iran-and-how-to-protect-yourself/)
    - [Hacked Prayer App Weaponized in Cyber Operations Amid US–Israel Strikes on Iran](https://cyberpress.org/hacked-prayer-app-weaponized-in-cyber-operations-amid-us-israel-strikes-on-iran/)

---

*Last Updated: March 3, 2026* 
