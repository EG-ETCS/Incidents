# Signal Call-Termination Vulnerability - CVE-2026-113380
![alt text](images/Signal.png)

**Signal**{.cve-chip} **RingRTC**{.cve-chip} **CVE-2026-113380**{.cve-chip} **CVSS 9.3**{.cve-chip} **Privacy Exposure Risk**{.cve-chip}

## Overview

A critical vulnerability was discovered in Signal's RingRTC calling library, which manages voice and video calls.

A malicious call participant could overwhelm the library's internal event queue and prevent a hang-up request from being processed correctly. As a result, a victim might believe a call has ended while audio and potentially video remain active.

## Technical Details

CVE-2026-113380 is classified as CWE-754 (improper checking for unusual or exceptional conditions). It affects RingRTC versions earlier than 2.72.0.

The reported attack saturates the call finite-state-machine (FSM) event queue, delaying or blocking call termination handling. Reported severity is CVSS 4.0 score 9.3 (Critical).

No claim in the cited reporting establishes a break of Signal's end-to-end encryption model; this issue concerns call-termination behavior and privacy exposure risk if media remains active unexpectedly.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Vulnerability** | CVE-2026-113380 |
| **Weakness Class** | CWE-754 |
| **Affected Component** | Signal RingRTC calling library |
| **Affected Versions** | RingRTC prior to 2.72.0 |
| **Attack Prerequisite** | Malicious participant in an active call |
| **Exploit Method** | FSM queue saturation to disrupt termination processing |
| **Severity** | CVSS 4.0: 9.3 (Critical) |
| **Encryption Status** | No direct evidence of E2EE cryptographic break in cited sources |

## Affected Products

- Signal clients on Android, iOS, Windows, macOS, and Linux using vulnerable RingRTC versions.
- Any software integrating RingRTC versions earlier than 2.72.0.

## Attack Scenario

1. The attacker establishes a Signal call with the victim.
2. The attacker floods the call FSM event queue with excessive call-related events.
3. The victim attempts to hang up, but termination processing is delayed or blocked.
4. The victim assumes the call has ended while audio and potentially video may remain active.
5. The attacker may receive sensitive conversations or visual information if transmission continues.

## Impact Assessment

=== "Privacy and Confidentiality Impact"

    - Potential unauthorized exposure of private conversations
    - Possible leakage of sensitive visual information if camera stream remains active

=== "Operational/User-Trust Impact"

    - Failure of expected call-termination behavior
    - Reduced user confidence in call-state indicators

=== "Exploitation Context"

    - No confirmed widespread exploitation reported in cited coverage
    - Vulnerability does not itself demonstrate a break in Signal end-to-end encryption

## Mitigation Strategies

1. Update Signal on Android, iOS, Windows, macOS, and Linux to the latest available version.
2. If integrating RingRTC directly, upgrade to version 2.72.0 or later.
3. Verify calls are fully disconnected after hanging up.
4. Check microphone and camera activity indicators after calls.
5. If media activity persists, temporarily revoke app permissions and investigate.
6. For developers, ensure termination requests can bypass saturated queues and add explicit shutdown timeout controls.

## Resources and References

!!! info "Public Reporting"
    1. [Signal bug could keep your mic - and camera - on after hangup](https://www.theregister.com/security/2026/10/21/signal-bug-could-keep-your-mic-and-camera-on-after-hangup/5304528)
    2. [Signal flaw could expose audio and video even after users hang up](https://www.helpnetsecurity.com/2026/10/22/signal-ringrtc-vulnerability-cve-2026-113380/)
    3. [Signal Vulnerability Lets Malicious Callers Block Hang-Ups](https://www.securityweek.com/signal-vulnerability-lets-malicious-callers-block-hang-ups/)

---

*Last Updated: October 29, 2026*
