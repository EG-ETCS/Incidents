---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![Apple WebKit](Week51/images/useAfterFree.png)
    :material-apple:{ .lg .middle } **CVE-2025-43529 Apple WebKit Use-After-Free Vulnerability**

    **Use-After-Free**{.cve-chip}  
    **Remote Code Execution**{.cve-chip}  
    **Actively Exploited**{.cve-chip}  
    ---------------------------------

    Critical use-after-free vulnerability in WebKit HTML parser affects **iOS, iPadOS, macOS, Safari** and third-party apps using WebKit. Malicious web content triggers **memory corruption** leading to crashes or **arbitrary code execution**. **Actively exploited in sophisticated attacks** - Added to CISA KEV. Can lead to **device compromise, spyware installation, and data theft**. Affects both Apple and non-Apple products using WebKit. **Update to Safari 26.2+** and apply latest iOS/iPadOS/macOS patches immediately. Enable automatic updates on all devices. CWE-416.

    [:octicons-arrow-right-24: View Full Details](Week51/useAfterFree.md)

-   ![Fortinet FortiCloud](Week51/images/forticloud.png)
    :material-shield-lock:{ .lg .middle } **CVE-2025-59718/59719 Fortinet FortiCloud SSO Authentication Bypass**

    **Authentication Bypass**{.cve-chip}  
    **SAML Signature Bypass**{.cve-chip}  
    **Critical**{.cve-chip}  
    ---------------------------------

    Critical authentication bypass in Fortinet FortiCloud SSO feature. Improper verification of **SAML cryptographic signatures** allows **unauthenticated remote attackers** to gain **full administrative access** by crafting malicious SAML responses. Affects **FortiOS, FortiProxy, FortiSwitchManager, FortiWeb** when FortiCloud SSO enabled. Enables complete device compromise, firewall rule modification, and backdoor creation. **Patch immediately** or disable FortiCloud SSO. Fixed versions: FortiOS 7.6.4+/7.4.9+, FortiProxy 7.6.4+/7.4.11+, FortiWeb 8.0.1+/7.6.5+. CWE-347.

    [:octicons-arrow-right-24: View Full Details](Week51/forticloud.md)

-   ![SolarEdge SE3680H](Week51/images/solaredge.png)
    :material-solar-power:{ .lg .middle } **CVE-2025-36745 SolarEdge SE3680H Linux Kernel Vulnerabilities**

    **Unpatched Linux Kernel**{.cve-chip}  
    **Remote Code Execution**{.cve-chip}  
    **Unmaintained Components**{.cve-chip}  
    ---------------------------------

    Solar inverter shipped with **outdated, unpatched Linux kernel** containing multiple vulnerabilities. Allows attackers to achieve **remote code execution, privilege escalation, and information disclosure** without authentication. Affects SolarEdge SE3680H inverters up to firmware **v4.21** in **solar power installations**. Risks include **grid stability concerns, safety hazards, and lateral movement** in networks. Use of unmaintained third-party components (CWE-1104). **Contact SolarEdge for firmware updates**, isolate devices on segmented networks, and restrict management access. CVSS 8.6 (High).

    [:octicons-arrow-right-24: View Full Details](Week51/solaredge.md)

</div>
