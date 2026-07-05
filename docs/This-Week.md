---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![DuneSlide](2026/Week27/images/DuneSlide.png)

    **DuneSlide - Critical Cursor AI IDE Prompt Injection Vulnerabilities**

    **CVE-2026-50548**{.cve-chip} **CVE-2026-50549**{.cve-chip} **Prompt Injection**{.cve-chip} **Sandbox Escape**{.cve-chip} **AI IDE RCE**{.cve-chip}

    DuneSlide is a vulnerability chain in Cursor versions before 3.0 where attacker-controlled content can trigger indirect prompt injection and sandbox escape, enabling arbitrary OS command execution on developer workstations. Impact includes credential and source-code theft, malware installation, and downstream software supply-chain risk.

    [Read more](2026/Week27/DuneSlide.md)

-   ![FatFs](2026/Week27/images/FatFs.png)

    **Multiple Unpatched Vulnerabilities in FatFs Filesystem Library**

    **CVE-2026-6682**{.cve-chip} **Embedded Systems**{.cve-chip} **FAT/exFAT Parsing**{.cve-chip} **Memory Corruption**{.cve-chip} **Potential RCE**{.cve-chip}

    Seven unpatched vulnerabilities in the FatFs filesystem library can be triggered by malicious FAT/exFAT metadata from removable media, leading to crashes, memory corruption, and possible code execution on embedded devices that integrate the library.

    [Read more](2026/Week27/FatFs.md)

-   ![Bad Epoll](2026/Week27/images/BadEpoll.png)

    **Bad Epoll (CVE-2026-46242)**

    **CVE-2026-46242**{.cve-chip} **Linux Kernel LPE**{.cve-chip} **Use-After-Free**{.cve-chip} **Race Condition**{.cve-chip} **Android Impact**{.cve-chip}

    Bad Epoll is a Linux kernel epoll/eventpoll race-condition vulnerability that enables unprivileged local users to gain root privileges via use-after-free memory corruption, affecting Linux and Android systems on vulnerable kernels.

    [Read more](2026/Week27/BadEpoll.md)

-   ![NetNut](2026/Week27/images/NetNut.png)

    **NetNut Residential Proxy Network Disruption**

    **Residential Proxy Abuse**{.cve-chip} **Android Botnet**{.cve-chip} **NetNut Disruption**{.cve-chip} **FBI Operation**{.cve-chip} **BadBox 2.0**{.cve-chip}

    Google and the FBI disrupted NetNut, a malicious residential proxy service powered by about 2 million compromised Android-based devices, which attackers used to hide identity during credential attacks, malware delivery, and command-and-control activity.

    [Read more](2026/Week27/NetNut.md)

</div>
