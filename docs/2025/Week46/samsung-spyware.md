# LANDFALL Android Spyware — Samsung Galaxy Zero-Day Campaign

**CVE-2025-21042**{.cve-chip}
**Android Spyware / Zero-day Exploit**{.cve-chip}
**Remote Code Execution**{.cve-chip}

## Overview

A previously unknown Android spyware family dubbed **LANDFALL** was used in targeted attacks against Samsung Galaxy devices in **Iraq, Iran, Turkey, and Morocco**. The campaign exploited a zero‑day vulnerability **CVE‑2025‑21042** (CVSS 8.8) — an out‑of‑bounds write in Samsung's proprietary image codec library (`libimagecodec.quram.so`) — enabling remote code execution via crafted **DNG** (Digital Negative) image files.

## Technical Specifications

| **Attribute**             | **Details**                                                                           |
| ------------------------- | ------------------------------------------------------------------------------------- |
| **CVE ID**                | CVE-2025-21042                                                                        |
| **Vulnerability Type**    | Out‑of‑bounds write → Remote Code Execution                                           |
| **Exploited Component**   | `libimagecodec.quram.so` (Samsung image decoder)                                      |
| **Attack Vector**         | Malicious DNG image (delivered via messaging apps such as WhatsApp)                   |
| **Complexity**            | Low to Medium (crafted image + embedded payload)                                      |
| **Privileges Required**   | None (triggered by preview/display)                                                   |
| **User Interaction**      | Likely none (preview/processing)                                                      |
| **CVSS Score**            | 8.8 (High)                                                                            |
| **Affected Devices / OS** | Galaxy S22, S23, S24, Z Fold 4, Z Flip 4 on Android 13–15 (before April 2025 patches) |

## Technical Details

* **Exploit chain:**

  1. Malicious DNG triggers an out‑of‑bounds write in `libimagecodec.quram.so`.
  2. The crafted DNG contains an embedded ZIP that extracts a shared object (SO) to disk.
  3. A secondary SO manipulates SELinux policy to escalate privileges and achieve persistence.
* **Payload & Capabilities:** LANDFALL provides modular surveillance capabilities: microphone/audio capture, geolocation, camera/photos, contacts, call logs, SMS, file exfiltration, and arbitrary command execution. It implements encrypted C2 communications and dynamic module loading.
* **Persistence & Evasion:** The spyware modifies SELinux, disables debugging and logging, uses certificate pinning and encrypted C2, and resists removal across reboots.
* **Attribution:** No definitive attribution; however, some C2 infrastructure overlaps with known APT clusters (e.g., Stealth Falcon / FruityArmor).

## Attack Scenario

1. **Recon & Targeting:** Adversary selects high‑value targets and prepares a crafted DNG lure.
2. **Delivery:** Malicious DNG is sent via WhatsApp (or other messaging channels). The wafer may be disguised with filenames resembling legitimate images.
3. **Trigger:** The victim's device processes the DNG (gallery preview or messaging app thumbnail generation), triggering the vulnerable decoder and achieving RCE.
4. **Payload Drop:** Embedded ZIP extracts and loads malicious SO libraries; SELinux is manipulated for privilege escalation.
5. **C2 Communication:** LANDFALL beacons to attacker C2 over encrypted channels and pulls additional modules.
6. **Surveillance & Exfiltration:** Data is collected and exfiltrated to attacker infrastructure.
7. **Persistence:** Malware ensures survival across reboots and attempts to hide from user and security tools.

## Impact

* **Full device takeover**: Persistent root control and comprehensive data exfiltration.
* **Espionage**: Audio, location, messages, and sensitive files exposed; severe privacy and national security implications for targeted users.
* **Widespread risk**: Affected models were widely deployed prior to the April 2025 patch, potentially exposing large user populations in the region.
* **APT‑grade operations**: The complexity and infrastructure point to a sophisticated adversary.

## Mitigations

* **Patch**: Install Samsung’s April 2025 security update or later immediately.
* **Avoid opening suspicious media**: Do not preview or open unsolicited images, especially DNG files.
* **Restrict DNG handling**: Block or disable automatic processing of DNGs from untrusted sources in messaging apps where possible.
* **Mobile forensics**: Examine WhatsApp/media directories for suspicious DNGs and embedded SO files if compromise is suspected.
* **Enterprise guidance**: Advise high‑risk personnel (NGOs, journalists, government staff) to apply patches, limit app permissions, and use hardened devices.
* **Monitoring & detection**: Watch for unusual SELinux policy changes, unexpected SO files, and anomalous network beaconing from devices.

## Indicators & IOC

* Malicious filenames observed: `WhatsApp Image 2025-02-10 at 4.54.17 PM.jpeg`, `IMG-20240723-WA0000.jpg` (actually DNG with embedded ZIP)
* C2 infrastructure and domains reported in vendor writeups (consult references below for exact IOCs).

## Resources and References

!!! info "Official Documentation"
- [LANDFALL Android spyware targeted Samsung phones via zero‑day - SecurityWeek](https://www.securityweek.com/landfall-android-spyware-targeted-samsung-phones-via-zero-day/)
- [LANDFALL abused zero‑day to hack Samsung Galaxy phones – TechCrunch](https://techcrunch.com/2025/11/07/landfall-spyware-abused-zero-day-to-hack-samsung-galaxy-phones/)
- [Samsung zero‑click flaw exploited to hack devices – The Hacker News](https://thehackernews.com/2025/11/samsung-zero-click-flaw-exploited-to.html)
- [LANDFALL spyware exploited Samsung zero‑day in Middle East attacks – SecurityAffairs](https://securityaffairs.com/184331/security/landfall-spyware-exploited-samsung-zero-day-cve-2025-21042-in-middle-east-attacks.html)
- [Landfall is new commercial‑grade Android spyware – Unit42](https://unit42.paloaltonetworks.com/landfall-is-new-commercial-grade-android-spyware/)

!!! warning "Risk Level: Critical"
LANDFALL enables persistent, stealthy surveillance and full device compromise. Prioritise patching and forensic investigation for suspected victims.
