---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

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
