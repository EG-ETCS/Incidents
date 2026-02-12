---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![notepad](2026/Week6/images/notepad.png)

    **Windows 11 Notepad Markdown Remote Code Execution Vulnerability**

    **CVE-2026-20841**{.cve-chip} **Remote Code Execution**{.cve-chip} **Markdown Link Handling**{.cve-chip} **CVSS 8.8**{.cve-chip} **Windows 11**{.cve-chip}

    A critical flaw in Windows 11 Notepad's Markdown link handling allowed attackers to trick users into executing malicious links in .md files. Clicking specially crafted links could launch unverified protocols and run remote or local files without normal Windows security warnings.

    The vulnerability, patched in February 2026, required user interaction but could lead to full system compromise if the user had administrative privileges. Post-fix Notepad versions display warnings when clicking non-HTTP/HTTPS links.

    [:octicons-arrow-right-24: Read more](2026/Week6/notepad.md)

-   ![senegal](2026/Week6/images/senegal.png)

    **Senegal National ID Office Ransomware Attack**

    **Ransomware**{.cve-chip} **National ID Systems**{.cve-chip} **Data Breach**{.cve-chip} **Green Blood Group**{.cve-chip} **Biometric Data**{.cve-chip}

    Senegal's Directorate of File Automation (DAF) was hit by a ransomware attack that forced suspension of national ID and passport issuance. The Green Blood Group claimed exfiltration of approximately 139 GB of sensitive citizen data including biometric records, immigration documents, and ID card information.

    The breach compromised card personalization servers and prompted immediate network isolation, credential rotation, and deployment of Malaysian cybersecurity experts from IRIS Corporation for forensic investigation and recovery.

    [:octicons-arrow-right-24: Read more](2026/Week6/senegal.md)

-   ![apple](2026/Week6/images/apple.png)

    **Apple Zero-Day Exploitation (CVE-2026-20700)**

    **CVE-2026-20700**{.cve-chip} **Zero-Day**{.cve-chip} **dyld Memory Corruption**{.cve-chip} **Targeted Attacks**{.cve-chip} **Spyware**{.cve-chip}

    Apple patched a zero-day flaw in dyld (Dynamic Link Editor) used in extremely sophisticated attacks targeting specific individuals. The memory corruption vulnerability allowed attackers with memory write capability to execute arbitrary code, likely chained with WebKit exploits for full system compromise.

    The attacks are believed to be associated with commercial surveillance or mercenary spyware campaigns. Emergency patches released for iOS, iPadOS, macOS, watchOS, tvOS, and visionOS address the actively exploited vulnerability.

    [:octicons-arrow-right-24: Read more](2026/Week6/apple.md)

-   ![zerodayrat](2026/Week6/images/zerodayrat.png)

    **ZeroDayRAT Spyware Grants Attackers Total Access to Mobile Devices**

    **Mobile Spyware**{.cve-chip} **Remote Access Trojan**{.cve-chip} **Stalkerware**{.cve-chip} **Android**{.cve-chip} **iOS**{.cve-chip}

    ZeroDayRAT is a commercially available mobile spyware toolkit marketed via underground channels like Telegram that enables complete remote access to Android and iOS devices. It provides keylogging, live camera/microphone access, GPS tracking, clipboard hijacking for crypto theft, SMS interception including OTP codes, and 2FA bypass capabilities.

    This "textbook stalkerware" represents a dangerous shift toward nation-state-level surveillance tools becoming available to criminal actors. Distribution occurs through smishing, phishing campaigns, and malicious APKs that trick victims into installing the spyware via social engineering.

    [:octicons-arrow-right-24: Read more](2026/Week6/zerodayrat.md)

</div>
