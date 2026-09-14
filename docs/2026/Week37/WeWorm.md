# WeWorm - WeChat Zero-Click Worm
![alt text](images/WeWorm.png)

**WeChat Security**{.cve-chip} **Zero-Click Exploit**{.cve-chip} **Worm Propagation**{.cve-chip} **Cross-Platform Risk**{.cve-chip} **Account Takeover**{.cve-chip}

<iframe width="667" height="1186" src="https://www.youtube.com/embed/OQdagtqKoXg" title="WeWorm: the first zero-click worm to spread through WeChat calls across iOS and Android" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

## Overview

Security researchers presented a proof-of-concept worm named **WeWorm** that abused a vulnerability in WeChat incoming-call handling. The reported exploit path required no user interaction: victims did not need to answer the call, click links, or open messages.

Successful exploitation could compromise the victim's WeChat account and use that trusted account to target additional contacts, enabling self-propagating spread through contact graphs.

## Technical Details

The demonstrated chain used specially crafted incoming call data processed automatically by the target client.

### Exploitation Mechanics

- Vulnerability associated with handling of crafted incoming WeChat call traffic.
- Researchers reported memory-corruption behavior that could be developed into code execution within the WeChat app context.
- Exploitation was demonstrated as zero-click from victim perspective.

### Propagation Model

- After account compromise, the worm could initiate malicious calls to additional contacts.
- Propagation was demonstrated between Android and iOS endpoints, indicating a potential cross-platform infection path.
- Social trust and contact-network reach amplify spread potential.

### Scope and Evidence Context

- Public reporting describes this as a researcher proof-of-concept and demonstrated attack path.
- Tencent reportedly issued patched client versions and additional server-side protections after disclosure.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Campaign/PoC Name** | WeWorm |
| **Target Platform** | WeChat client ecosystem |
| **Initial Vector** | Specially crafted incoming call data |
| **User Interaction Required** | None (zero-click in demonstrated chain) |
| **Core Exploit Outcome** | WeChat account compromise and control |
| **Propagation Pattern** | Contact-to-contact malicious call propagation |
| **Cross-Platform Exposure** | Demonstrated across Android and iOS |
| **Operational Classification** | Proof-of-concept worm with high real-world abuse potential |

## Affected Products

- WeChat client installations vulnerable at time of research demonstration.
- Android and iOS devices running affected versions.
- Accounts and communication workflows dependent on WeChat trust relationships.

## Attack Scenario

1. Attacker or already compromised WeChat account sends a specially crafted call to a contact.
2. Target WeChat client processes malicious call data automatically.
3. Exploitation occurs without answer/click/open interaction by the victim.
4. Attacker gains control over victim's WeChat account behavior.
5. Compromised account is used to initiate additional malicious calls.
6. Worm-like propagation repeats through contact graph.

## Impact Assessment

=== "Primary Account Impact"

    - Unauthorized access and control of WeChat accounts
    - Ability to send messages, initiate calls, and impersonate victims

=== "Secondary Abuse Potential"

    - Credential or sensitive message exposure via account takeover context
    - Social-engineering amplification through trusted-contact abuse
    - Rapid scaling risk because infection can propagate without direct user interaction

=== "Broader Ecosystem Risk"

    - Potential disruption to personal, business, and service-linked communication workflows
    - Elevated risk where WeChat is used for operational or commercial coordination

## Mitigation Strategies

### Patch Client and Device Software

- Update WeChat to the latest official app-store release.
- Keep Android and iOS devices fully patched.

### Strengthen Account Security

- Enable available account-security hardening and MFA features.
- Review active sessions and revoke unknown or unauthorized devices.

### Monitor for Compromise Indicators

- Monitor unusual call patterns, messaging behavior, login anomalies, and account-activity deviations.
- Establish procedures to detect account takeover and impersonation attempts.

### Organizational Preparedness

- Organizations relying on WeChat should define incident playbooks for communication-account compromise.
- Coordinate user awareness and rapid containment actions for suspicious call-chain activity.

### Vendor Guidance Context

- Reporting indicates Tencent released patched versions and additional server-side mitigations.
- Apply both client updates and any vendor-recommended account/security controls.

## Resources and References

!!! info "Public Reporting and Research"
    - [WeWorm | Calif](https://calif.io/research/weworm)
    - [WeChat worm could pwn a friend before they even answered the call](https://www.theregister.com/security/2026/09/09/wechat-worm-could-pwn-a-friend-before-they-even-answered-the-call/5295234)
    - [WeChat Zero-Click Worm: Captured iPhone/Android Accounts](https://www.secnews.gr/en/731528/wechat-zero-click-worm-logariasmoi/)
    - [WeChat Worm Can Hijack Accounts Without Victims Answering Calls](https://securityaffairs.com/198688/hacking/wechat-worm-can-hijack-accounts-without-victims-answering-calls.html)

---

*Last Updated: September 14, 2026*