# C0XMO Botnet Spreads via DD-WRT Router Flaw, Kills Rival Malware
![alt text](images/C0XMO.png)

**CVE-2021-27137**{.cve-chip} **CVE-2015-2051**{.cve-chip} **CVE-2022-35914**{.cve-chip} **Gafgyt Variant**{.cve-chip} **IoT Botnet**{.cve-chip} **DDoS**{.cve-chip}

## Overview

A new Gafgyt botnet variant named **C0XMO** is actively compromising unpatched DD-WRT-based routers and other Linux-embedded devices by exploiting **CVE-2021-27137**, a stack buffer overflow in DD-WRT's UPnP service reachable over UDP port 1900. Once a device is compromised, C0XMO downloads architecture-specific payloads (ARM, MIPS, x86, PowerPC), establishes cron-based persistence, registers the device with its command-and-control infrastructure, and aggressively kills competing botnet processes and persistence mechanisms to maintain exclusive control. A modular Python scanner enables cross-platform lateral movement into D-Link routers, GLPI instances, Avtech DVR cameras, Zyxel devices, and Android devices via exposed ADB — significantly expanding the botnet's potential footprint. Enrolled devices are subsequently weaponized for DDoS operations supporting approximately 19 attack methods including UDP/TCP floods and NTP amplification.

## Technical Specifications

| Attribute | Details |
|---|---|
| **Primary CVE** | CVE-2021-27137 — DD-WRT UPnP stack buffer overflow (UDP 1900 / SSDP M-SEARCH) |
| **Additional CVEs** | CVE-2015-2051 (D-Link HNAP), CVE-2022-35914 (GLPI), CVE-2016-15047 / CVE-2025-34054 (Avtech DVR) |
| **Malware Family** | Gafgyt variant (C0XMO) |
| **Target Architectures** | ARM, MIPS, x86_64, PowerPC, Android (via ADB) |
| **Payload Drop Locations** | `/tmp/.cache`, `/tmp/.sys`, `/var/tmp/.sys`, `/dev/shm/.sys` |
| **Persistence Mechanism** | Cron jobs (re-execution every ~15 minutes) |
| **C2 Infrastructure** | `85[.]215[.]131[.]70`, `217[.]160[.]125[.]125:15527`, `216.131.80.130/150/119` |
| **C2 Handshake** | Magic string `669787761736865726500` + shared secret |
| **DDoS Methods** | ~19 methods including UDP/TCP flood, NTP amplification, Cloudflare/UDP bypass |
| **Lateral Movement** | Python scanner (paramiko, requests, bs4) — SSH/Telnet brute-force + HTTP CVE exploitation |
| **Distinguishing Behavior** | Kills competing botnet processes and removes rival persistence (cron jobs, startup scripts) |

## Affected Products

- **DD-WRT routers** running firmware versions vulnerable to CVE-2021-27137 (UPnP stack buffer overflow) — primary entry point
- **D-Link devices** — HNAP command execution via CVE-2015-2051
- **GLPI instances** — code injection via CVE-2022-35914 (`htmLawedTest.php`)
- **Avtech DVR cameras** — authentication bypass / command execution via CVE-2016-15047 and CVE-2025-34054
- **Zyxel devices** — targeted by the Python scanner module
- **Android devices** — compromised via exposed Android Debug Bridge (ADB)

## Attack Scenario

1. **Target identification** — C0XMO operators scan the internet for DD-WRT routers with UPnP enabled and UDP port 1900 accessible; victims are typically home users or small businesses running older DD-WRT firmware that has not been updated since before CVE-2021-27137 was patched

2. **Initial exploitation** — Crafted SSDP M-SEARCH packets with an oversized `ST:uuid` value are sent to the target router's UPnP service, triggering the CVE-2021-27137 stack buffer overflow and yielding unauthenticated remote code execution as root

3. **Payload download and installation** — The exploit shell retrieves an architecture-appropriate ELF binary (the C0XMO/Gafgyt payload) and drops it into `/tmp/.cache` or hidden directories (`/tmp/.sys`, `/var/tmp/.sys`, `/dev/shm/.sys`), sets executable permissions, and executes it

4. **Persistence and C2 registration** — Cron jobs are created to re-execute the payload every ~15 minutes; the malware connects to C2 servers using the magic handshake string, enrolling the device in the botnet

5. **Rival malware elimination** — C0XMO scans for other botnet binaries and persistence entries (Mirai/Gafgyt variants), terminates their processes, and removes their cron jobs and startup scripts to ensure exclusive control of the compromised device

6. **Lateral movement and expansion** — The Python scanner module (using paramiko, requests, bs4) begins brute-forcing Telnet/SSH with weak credentials and exploiting HTTP-based CVEs (GLPI, Avtech DVR, D-Link, Zyxel); it also attempts to compromise Android devices via exposed ADB; for each newly compromised host, the correct architecture-specific binary is downloaded and installed, growing the botnet across routers, IoT devices, DVRs, and Android endpoints

7. **DDoS operations** — Enrolled devices receive C2 commands to launch DDoS attacks against designated targets using any of ~19 supported methods, including UDP/TCP floods, NTP amplification, and Cloudflare bypass techniques

## Impact

=== "Individual Users and Small Businesses"

    - Compromised routers and IoT devices become active DDoS botnet nodes, consuming available bandwidth, degrading internet performance, and risking ISP abuse complaints or service suspension
    - C0XMO's cross-platform propagation means multiple devices in the same environment — router, DVR, IoT sensors, Android devices — may be simultaneously compromised, dramatically increasing cleanup complexity
    - Device owners typically have no visible indication of compromise until performance degradation or ISP notification occurs

=== "Organizations and ISPs"

    - Large numbers of C0XMO-enrolled devices can be directed to launch significant DDoS campaigns against internet services and critical infrastructure, with traffic appearing to originate from diverse consumer residential IP addresses
    - Unmanaged or "forgotten" DD-WRT and IoT devices in corporate networks become stepping stones for lateral movement, particularly when they sit in sensitive or flat network segments adjacent to critical systems
    - ISPs face increased abuse traffic volumes and support burden from customer devices enrolled in botnet operations

=== "Security Landscape"

    - C0XMO exemplifies continued Gafgyt-class botnet evolution: modular architecture, multi-architecture cross-platform payloads, reuse of old but widely unpatched CVEs (some dating to 2015), and active anti-competitor behavior that reduces botnet fragmentation on infected hosts
    - The botnet highlights the persistent and systemic risk from legacy, unmaintained router firmware and the widespread failure to patch IoT and embedded devices — CVE-2021-27137 was disclosed in 2021, yet remains exploitable at scale in 2026
    - High criticality for exposed DD-WRT and IoT environments (unauthenticated RCE + multi-CVE chain); significant ongoing availability threat at the ecosystem level

## Mitigations

### Patch and Configuration

- **Update firmware** — upgrade DD-WRT routers and all other affected devices (D-Link, GLPI servers, Avtech DVR cameras) to firmware and software versions that address the listed CVEs; replace hardware that no longer receives vendor security updates
- **Disable UPnP where not explicitly required** — disabling UPnP on routers eliminates the primary C0XMO entry point (CVE-2021-27137); at minimum, block external UDP port 1900 at the perimeter firewall to prevent internet-origin SSDP exploitation
- **Lock down management interfaces** — ensure router admin panels, Telnet/SSH, and Android ADB are not exposed to the internet; restrict access to internal or VPN-only segments; disable Telnet wherever possible and enforce SSH with key-based authentication

### Network Monitoring and Detection

- **Monitor for exploitation and botnet traffic indicators**:
    - Unusual UDP 1900 traffic or spikes in SSDP M-SEARCH requests
    - Outbound connections to known C2 addresses: `85[.]215[.]131[.]70`, `217[.]160[.]125[.]125:15527`, `216.131.80.130/150/119` range
    - Unexplained high-rate outbound UDP/TCP flows consistent with DDoS participation
- **Hunt for malware artifacts** on routers, IoT, and Linux hosts:
    - Hidden directories: `/tmp/.sys`, `/var/tmp/.sys`, `/dev/shm/.sys`
    - ELF binaries with 755 permissions in `/tmp` and similar writable locations
    - Unexpected cron jobs executing at short intervals (e.g., every 15 minutes)

### IoT and Router Environment Hardening

- **Use unique, strong admin passwords** and disable default or vendor-provided credentials on all network-connected devices
- **Segment IoT and router management networks** from core corporate and OT systems to prevent lateral movement from a compromised embedded device into sensitive infrastructure
- **Maintain an asset inventory** for all routers and embedded devices and include them in routine patch cycles and security review processes

### Response if Compromised

- **Factory-reset the device**, then immediately flash the latest available firmware, reconfigure securely (disable UPnP, remote management, default accounts), and change all administrative credentials
- **Rotate Wi-Fi and VPN credentials** if the compromised router handled those services; monitor for recurring reinfection, which indicates other unpatched IoT devices in the environment are re-enrolling the cleaned host

## Resources

!!! info "Open-Source Reporting"
    - [C0XMO Botnet Spreads via DD-WRT Router Flaw, Kills Rival Malware — BleepingComputer](https://www.bleepingcomputer.com/news/security/c0xmo-botnet-spreads-via-dd-wrt-router-flaw-kills-rival-malware/amp/)
    - [Inside Cross-Platform Propagation of New Gafgyt Variant C0XMO — Fortinet Threat Research](https://www.fortinet.com/uk/blog/threat-research/inside-cross-platform-propagation-of-new-gafgyt-variant-c0xmo)
    - [C0XMO: A New Gafgyt Variant with Cross-Platform Propagation — SOC Prime](https://socprime.com/active-threats/c0xmo-a-new-gafgyt-variant-with-cross-platform-propagation/)
    - [New Gafgyt Variant Targets Multiple Linux Architectures — Cyber Security News](https://cybersecuritynews.com/new-gafgyt-variant-targets-multiple-linux-architectures/)

---

*Last Updated: June 8, 2026*