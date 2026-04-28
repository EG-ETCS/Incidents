# Firefox Vulnerability Allows Tor User Fingerprinting
![alt text](images/Firefox.png)

**CVE-2026-6770**{.cve-chip}  **Firefox/Tor Browser**{.cve-chip}  **IndexedDB Privacy Flaw**{.cve-chip}  **Cross-Site Linkability**{.cve-chip}

## Overview
CVE-2026-6770 is a privacy vulnerability in Firefox-based browsers, including Tor Browser, that allows websites to derive a stable process-lifetime identifier via IndexedDB behavior. This can enable cross-site tracking even when users expect isolation in Private Browsing or Tor's New Identity mode.

Mozilla classified the issue as medium severity, but practical privacy impact is significantly higher for anonymity-focused use cases.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **CVE** | CVE-2026-6770 |
| **Affected Component** | Storage: IndexedDB (`indexedDB.databases()`) |
| **Affected Products** | Firefox, Firefox ESR, Tor Browser, other Gecko-based builds |
| **Root Cause** | Deterministic process-scoped ordering of IndexedDB database metadata enabling cross-origin correlation |
| **Fingerprint Primitive** | Sites hash observed database-order permutation into a stable process-lifetime ID |
| **Privacy Boundary Failure** | Identifier can survive reloads and private-session boundaries while process remains alive |
| **Tor-Specific Risk** | Linkability persisted across New Identity events when process reuse occurred |
| **Fix Behavior** | Output ordering canonicalization/randomization to remove cross-origin entropy |
| **Patched Versions** | Firefox 150+, Firefox ESR 140.10.0+, Tor Browser 15.0.10+ |

## Affected Products
- Firefox-based browsers running vulnerable builds prior to fixes
- Tor Browser users relying on New Identity for session unlinkability
- Privacy-focused users depending on Private Browsing semantics
- Organizations with unmanaged browser update cadence for sensitive users

## Attack Scenario
1. **Identifier Seeding**:
   Website A creates/observes a known IndexedDB database set and records the returned order from `indexedDB.databases()`.

2. **Process-Lifetime ID Creation**:
   The observed order is encoded/hashed into an identifier tied to current browser process state.

3. **Cross-Site Correlation**:
   Website B repeats the same procedure and derives matching identifier within same process lifetime.

4. **Private-Mode Linking**:
   Tracking persists across private windows/sessions until full browser process restart.

5. **Tor Privacy Impact**:
   In affected Tor Browser behavior, New Identity may not fully break this process-level correlation.

## Impact Assessment

=== "Integrity"
    * No direct code execution or memory corruption control impact
    * Core impact is trust-boundary failure in browser privacy isolation behavior
    * User expectations for session separation are undermined

=== "Confidentiality"
    * Enables cross-site and cross-session behavioral correlation without cookies
    * Weakens anonymity guarantees for privacy-sensitive users and Tor workflows
    * Facilitates richer profiling by ad-tech, analytics, or hostile trackers

=== "Availability"
    * Limited direct availability impact on systems/services
    * Indirect operational risk for high-sensitivity users relying on anonymity protections
    * Elevated incident-response/privacy-remediation effort for affected organizations

## Mitigation Strategies

### For Users
- Update immediately to Firefox 150+, ESR 140.10.0+, and Tor Browser 15.0.10+.
- Fully restart the browser process after updating (closing windows alone may be insufficient pre-fix).
- For high-risk activities, use stricter isolation (separate browser instances/VMs per task).

### For Organizations and Privacy Teams
- Accelerate browser patch deployment across managed fleets.
- Apply script/isolation controls for high-risk user groups where operationally feasible.
- Update privacy threat models and guidance to account for browser-implementation linkability edge cases.

### For Browser/Platform Hardening
- Avoid exposing process-stable high-entropy metadata across origins.
- Canonicalize/randomize outputs that may otherwise create linkable fingerprints.

## Resources and References

!!! info "Open-Source Reporting"
    - [Firefox Vulnerability Allows Tor User Fingerprinting | SecurityWeek](https://www.securityweek.com/firefox-vulnerability-allows-tor-user-fingerprinting/)
    - [Security Affairs: Firefox bug CVE-2026-6770 enabled cross-site tracking and Tor fingerprinting](https://securityaffairs.com/191374/security/firefox-bug-cve-2026-6770-enabled-cross-site-tracking-and-tor-fingerprinting.html?amp)
    - [Fingerprint Research: Firefox/Tor IndexedDB Privacy Vulnerability](https://fingerprint.com/blog/firefox-tor-indexeddb-privacy-vulnerability/)
    - [Privacy Guides Discussion: vulnerability linking Tor browsing activity](https://discuss.privacyguides.net/t/fingerprint-com-discovers-vulnerability-that-can-link-your-tor-browsing-together/37408)

---

*Last Updated: April 28, 2026*
