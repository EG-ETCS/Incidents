# Google Gemini Android Notification Prompt Injection Vulnerability
![alt text](images/Gemini.png)

**Prompt Injection**{.cve-chip} **Google Gemini**{.cve-chip} **Android**{.cve-chip} **Notification Abuse**{.cve-chip}

## Overview

Security researchers discovered a vulnerability in Google Gemini on Android that allowed malicious notifications from apps such as WhatsApp, Slack, Signal, Messenger, and SMS to manipulate the AI assistant through indirect prompt injection. Attackers could craft notification content that Gemini interpreted as commands instead of plain text.

![alt text](images/Gemini1.png)

## Technical Specifications

| Attribute | Details |
|---|---|
| **Vulnerability Type** | Indirect prompt injection via Android notifications |
| **Affected Service** | Google Gemini on Android (Utilities functionality) |
| **Affected Inputs** | Notifications from WhatsApp, Slack, Signal, Messenger, SMS, and similar apps |
| **Root Cause** | Unsafe interpretation of untrusted notification content as executable assistant context/commands |
| **Bypass Technique** | Fake Context Alignment to evade contextual safeguards |
| **Abuse Methods** | Hidden hyperlinks, multilingual prompts, invisible instruction embedding |
| **User Interaction** | Voice confirmation or assistant interaction can unintentionally approve malicious actions |
| **Malware Requirement** | None required |
| **Primary Risk** | Unauthorized assistant actions and manipulation of AI trust boundaries |
| **CVE ID** | Not publicly assigned in referenced reporting |

## Affected Products

- Android devices using Google Gemini with notification-processing Utilities features
- Users receiving attacker-crafted notifications through messaging and social apps
- High-risk hands-free usage contexts where voice confirmations are used quickly

## Attack Scenario

1. An attacker sends a crafted message through WhatsApp, Slack, SMS, or another messaging platform.
2. The malicious notification appears on the victim's Android device.
3. Gemini processes or reads the notification content.
4. Hidden instructions manipulate Gemini into performing unauthorized actions.
5. The victim unknowingly confirms the action through voice interaction or assistant prompts.

## Impact

=== "Integrity"

    - Unauthorized assistant-triggered actions can alter expected device and app behavior
    - Manipulation of AI memory and contextual state can influence later assistant decisions
    - Trust boundaries between user intent and assistant execution are weakened

=== "Confidentiality"

    - Increased phishing and social engineering effectiveness through AI-mediated interactions
    - Risk of exposing sensitive contextual information through misleading assistant responses
    - Potential misuse of assistant workflows to steer users to attacker-controlled destinations

=== "Availability"

    - Unwanted app launches and automated actions can disrupt normal user workflows
    - Joining meetings or triggering actions unexpectedly can interfere with communications reliability
    - Repeated abuse scenarios can reduce confidence and safe usability of assistant features

## Mitigations

### Immediate Actions

- Disable Gemini notification access if unnecessary
- Keep Android and Gemini services updated
- Carefully review on-screen prompts before confirming assistant actions

### Short-term Measures

- Limit AI assistant permissions to only required capabilities
- Avoid granting excessive automation permissions to AI assistants
- Strengthen mobile configuration baselines for assistant and notification permissions

## Resources

!!! info "Open-Source Reporting"
    - [WhatsApp, Slack Notifications Could Hijack Google Gemini on Android](https://thehackernews.com/2026/06/whatsapp-slack-notifications-could.html)
    - [Hackers could use poisoned WhatsApp and Slack notifications to take over your Google Gemini – and make it work on their behalf | TechRadar](https://www.techradar.com/pro/security/hackers-could-use-poisoned-whatsapp-and-slack-notifications-to-take-over-your-google-gemini-and-make-it-work-on-their-behalf)
    - [Google Gemini security flaw lets hackers hijack your Android phone via WhatsApp — what you need to know | Tom's Guide](https://www.tomsguide.com/ai/google-gemini-security-flaw-lets-hackers-hijack-your-android-phone-via-whatsapp-what-you-need-to-know)
    - [Malicious WhatsApp, Slack Alerts Could Have Exposed Millions of Android Users](https://www.techrepublic.com/article/news-whatsapp-slack-alerts-could-manipulate-gemini-android/)
    - [WhatsApp, Slack Notifications Could Hijack Google Gemini on Android — h4x.lat](https://h4x.lat/document/15336)

---

*Last Updated: June 7, 2026*
