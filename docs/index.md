---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![NFCShare](2026/Week23/images/NFCShare.png)

    **NFCShare Android Malware Campaign**

    **Android Malware**{.cve-chip} **NFC Theft**{.cve-chip} **Mobile Banking Fraud**{.cve-chip} **Social Engineering**{.cve-chip}

    A sophisticated Android malware campaign spreads via fake banking app updates on GitHub. It abuses Android NFC and EMV commands to steal payment card data and PINs, enabling contactless payment fraud and card emulation attacks against banking customers in Italy and Spain.

    [Read more](2026/Week23/NFCShare.md)

-   ![Kernel](2026/Week23/images/Kernel.png)

    **Linux Kernel nf_tables One-Character Privilege Escalation Vulnerability**

    **CVE-2026-23111**{.cve-chip} **Privilege Escalation**{.cve-chip} **Use-After-Free**{.cve-chip} **Container Escape**{.cve-chip}

    A single incorrect `!` operator in the Linux kernel's nf_tables subsystem triggers a Use-After-Free condition, allowing local low-privileged attackers to escalate to root. Public PoC exploit code is available. Confirmed on Debian Bookworm/Trixie and Ubuntu 22.04/24.04 LTS. Container escape is also possible in affected environments.

    [Read more](2026/Week23/Kernel.md)

-   ![Veeam](2026/Week23/images/Veeam.png)

    **Veeam Backup & Replication Remote Code Execution Vulnerability**

    **CVE-2026-44963**{.cve-chip} **Remote Code Execution**{.cve-chip} **Backup Infrastructure**{.cve-chip} **Ransomware Risk**{.cve-chip}

    A critical RCE vulnerability in Veeam Backup & Replication allows low-privileged domain users to compromise backup servers, enabling ransomware deployment and backup destruction. Affects version 12.3.2.4465 and earlier on domain-joined servers; patched in 12.3.2.4854.

    [Read more](2026/Week23/Veeam.md)

-   ![WinRAR](2026/Week23/images/WinRAR.png)

    **WinRAR CVE-2025-8088 Exploitation Campaign**

    **CVE-2025-8088**{.cve-chip} **Path Traversal**{.cve-chip} **Russia-Aligned APT**{.cve-chip} **Ukraine Targeting**{.cve-chip}

    Russia-aligned threat actors exploited a WinRAR path traversal flaw to deliver malware via malicious RAR archives targeting Ukrainian organizations. Attackers abused NTFS Alternate Data Streams to drop GIFTEDCROOK and other payloads into Startup folders, enabling persistence and credential theft.

    [Read more](2026/Week23/WinRAR.md)

-   ![RoguePlanet](2026/Week23/images/RoguePlanet.png)

    **RoguePlanet – Microsoft Defender Zero-Day Local Privilege Escalation**

    **Zero-Day**{.cve-chip} **Privilege Escalation**{.cve-chip} **Race Condition**{.cve-chip} **Microsoft Defender**{.cve-chip}

    A zero-day race condition (TOCTOU) in Microsoft Defender's remediation engine allows low-privileged local attackers to escalate to SYSTEM by abusing symbolic links and NTFS junctions during privileged file operations. No patch is yet available.

    [Read more](2026/Week23/RoguePlanet.md)

</div>