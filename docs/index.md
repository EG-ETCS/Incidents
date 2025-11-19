---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![Lynx+ Gateway](Week47/images/lynx.png)
    :material-lock-alert:{ .lg .middle } **Critical Lynx+ Gateway Vulnerabilities (CVE-2025-55034, CVE-2025-58083, CVE-2025-59780, CVE-2025-62765)**

    **Unauthorized Access & Info Disclosure**{.cve-chip}  
    **CVSS 9.2 Critical**{.cve-chip}  
    ---------------------------------

    Multiple flaws in General Industrial Controls Lynx+ Gateway allow a remote, unauthenticated attacker to brute‑force weak passwords, reset devices without authentication, retrieve sensitive configuration data, and capture plaintext credentials over the network. Affected versions (R08, V03, V05, V18) are widely deployed in OT environments, making coordinated attacks and lateral movement into industrial networks a serious risk.

    [:octicons-arrow-right-24: View Full Details](Week47/lynx.md)

-   ![Microsoft Graphics Component](Week47/images/ms-gfx.png)
    :material-server-security:{ .lg .middle } **Critical Microsoft Graphics Component Heap Buffer Overflow (CVE-2025-60724)**

    **Remote Code Execution**{.cve-chip}  
    **CVSS 9.8 Critical**{.cve-chip}  
    ---------------------------------

    A heap-based buffer overflow in the Microsoft Graphics Component (GDI+) allows a **remote, unauthenticated attacker** to execute arbitrary code over a network. The vulnerability is triggered when the system processes a specially crafted graphics file such as a metafile (WMF/EMF). It affects both desktop and server environments, and in some cases **does not require user interaction**.

    [:octicons-arrow-right-24: View Full Details](Week47/ms-gfx.md)

-   ![Google Chrome V8 Zero-Day](Week47/images/chrome-v8.png)
    :material-server-security:{ .lg .middle } **Critical Google Chrome V8 Engine Zero-Day (CVE-2025-13223)**

    **Remote Code Execution**{.cve-chip}  
    **CVSS 9.8 Critical**{.cve-chip}  
    ---------------------------------

    A **zero-day vulnerability** in Google Chrome’s V8 JavaScript engine allows **remote attackers** to execute arbitrary code on affected systems. The flaw is triggered by **maliciously crafted web content** that can bypass Chrome’s security mechanisms. Exploitation can lead to **full compromise of the browser process**, potentially allowing attackers to execute code in the context of the logged-in user.  

    Users should **update Chrome immediately** to the latest patched version to mitigate the risk.

    [:octicons-arrow-right-24: View Full Details](Week47/chrome-v8.md)

</div>
