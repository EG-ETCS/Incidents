# Xiaomi Redmi Buds Bluetooth RFCOMM Vulnerabilities
![alt text](images/buds.png)

**CVE-2025-13834**{.cve-chip}  **CVE-2025-13328**{.cve-chip}  **Bluetooth Memory Disclosure**{.cve-chip}  **Bluetooth Denial of Service**{.cve-chip}

## Overview
Security researchers at Korea University CCS Lab identified critical flaws in the proprietary Bluetooth RFCOMM implementation of Xiaomi Redmi Buds. 

The vulnerabilities allow nearby, unauthenticated attackers to both exfiltrate device memory contents and force the earbuds into an unusable state. 

One flaw mirrors a "Heartbleed over Bluetooth" scenario where malformed RFCOMM traffic elicits unintended memory disclosure, exposing sensitive real-time data such as phone numbers during live calls. 

Another flaw mishandles RFCOMM state transitions, enabling persistent denial-of-service until the attack stops. Widespread device adoption and proximity-based exploitability create significant privacy and availability risks.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **CVE IDs** | CVE-2025-13834 (Memory Disclosure), CVE-2025-13328 (DoS) |
| **Vulnerability Type** | Memory disclosure (Heartbleed-style), RFCOMM logic flaw leading to DoS |
| **Attack Vector** | Bluetooth proximity |
| **Authentication** | Not required (no pairing needed) |
| **Complexity** | Low |
| **User Interaction** | Not required |
| **Affected Versions** | Redmi Buds 3 Pro through 6 Pro (per advisories) |

## Affected Products
- Xiaomi Redmi Buds 3 Pro
- Xiaomi Redmi Buds 4 / 4 Pro
- Xiaomi Redmi Buds 5 / 5 Pro
- Xiaomi Redmi Buds 6 / 6 Pro
- Other Redmi Buds models sharing the proprietary RFCOMM stack (if unpatched)

![alt text](images/buds1.png)

## Attack Scenario
1. Attacker positions within Bluetooth range of the victim device
2. No pairing or authentication is required to interact with the earbuds
3. Attacker sends malformed RFCOMM messages that exploit parser/state flaws
4. Device responds by leaking unintended memory contents or enters a broken protocol state
5. Sensitive call data is exposed or the earbuds become unusable until the attack ceases

## Impact Assessment

=== "Integrity"
    * Protocol state corruption leading to unstable device behavior
    * Potential alteration of Bluetooth control flows during active sessions
    * Increased risk of further exploitation when device enters invalid states

=== "Confidentiality"
    * Memory disclosure of real-time call data (e.g., phone numbers, call metadata)
    * Exposure of buffered audio or control information over the air
    * Privacy violations without user awareness or consent

=== "Availability"
    * Persistent denial-of-service rendering earbuds unusable
    * Repeated crashes or lockups until attack traffic stops
    * Service disruption for calls, media playback, and device controls

## Mitigation Strategies

### Immediate Actions
- Apply vendor-issued firmware updates as soon as released
- Disable Bluetooth on devices when not actively in use
- Avoid using affected earbuds in high-risk or public environments until patched
- Power-cycle and re-pair devices if instability is observed

### Short-term Measures
- Enforce Bluetooth device allow-lists on host devices where supported
- Reduce Bluetooth visibility/discoverability to minimize unsolicited connections
- Monitor for abnormal Bluetooth traffic or repeated RFCOMM errors
- Educate users about proximity-based threats and symptoms (sudden audio drop, device lockup)

### Monitoring & Detection
- Use Bluetooth protocol analyzers to detect malformed RFCOMM frames targeting earbuds
- Alert on repeated connection attempts from unknown nearby devices
- Log and review Bluetooth stack errors/timeouts on paired hosts
- Track firmware version deployment to ensure updates are applied fleet-wide

## Resources and References

!!! info "Official Documentation"
    - [Redmi Buds Vulnerability Allow Attackers Access Call Data and Trigger Firmware Crashes](https://cybersecuritynews.com/redmi-buds-vulnerability/)
    - [Bluetooth "Heartbleed" and DoS Flaws Found in Xiaomi Redmi Buds, No Patch](https://securityonline.info/bluetooth-heartbleed-and-dos-flaws-found-in-xiaomi-redmi-buds-no-patch/)
    - [Redmi Buds Vulnerability Exposes Call Data and Enables Firmware Crashes](https://cyberpress.org/redmi-buds-vulnerability/)
    - [NVD - CVE-2025-13928](https://nvd.nist.gov/vuln/detail/CVE-2025-13928)
    - [VU#472136 - Information Leak and DoS Vulnerabilities in Redmi Buds 3 Pro through 6 Pro](https://kb.cert.org/vuls/id/472136)
    - [CISA Alerts on Redmi Buds 3 Pro through 6 Pro Vulnerabilities](https://decisioninsights.ai/advisory/cisa-alerts-on-redmi-buds-3-pro-through-6-pro-vulnerabilities/2026/01/)
