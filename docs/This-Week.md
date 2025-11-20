---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![FortiWeb Exploitation](Week47/images/fortiwebzero.png)
    :material-security:{ .lg .middle } **Critical FortiWeb Exploitation (CVE-2025-58034)**

    **OS Command Injection**{.cve-chip}  
    **CVSS 7.2 High**{.cve-chip}  
    ---------------------------------

    Fortinet’s FortiWeb Web Application Firewall (WAF) is vulnerable to an authenticated OS command injection flaw (**CVE-2025-58034**). Attackers can execute arbitrary OS commands via crafted HTTP requests or CLI commands, enabling full compromise of the device. Affected versions (8.0.0–8.0.1, 7.6.0–7.6.5, 7.4.0–7.4.10, 7.2.0–7.2.11, 7.0.0–7.0.11) are widely deployed, posing significant risks to enterprise environments.

    [:octicons-arrow-right-24: View Full Details](Week47/fortiwebzero.md)

-   ![Lynx+ Gateway](Week47/images/lynx.png)
    :material-lock-alert:{ .lg .middle } **Critical Lynx+ Gateway Vulnerabilities (CVE-2025-55034, CVE-2025-58083, CVE-2025-59780, CVE-2025-62765)**

    **Unauthorized Access & Info Disclosure**{.cve-chip}  
    **CVSS 9.2 Critical**{.cve-chip}  
    ---------------------------------

    Multiple flaws in General Industrial Controls Lynx+ Gateway allow a remote, unauthenticated attacker to brute‑force weak passwords, reset devices without authentication, retrieve sensitive configuration data, and capture plaintext credentials over the network. Affected versions (R08, V03, V05, V18) are widely deployed in OT environments, making coordinated attacks and lateral movement into industrial networks a serious risk.

    [:octicons-arrow-right-24: View Full Details](Week47/lynx.md)

-   ![Microsoft Graphics Component](Week47/images/ms-gfx.png)
    :material-microsoft:{ .lg .middle } **Critical Microsoft Graphics Component Heap Buffer Overflow (CVE-2025-60724)**

    **Remote Code Execution**{.cve-chip}  
    **CVSS 9.8 Critical**{.cve-chip}  
    ---------------------------------

    A heap-based buffer overflow in the Microsoft Graphics Component (GDI+) allows a **remote, unauthenticated attacker** to execute arbitrary code over a network. The vulnerability is triggered when the system processes a specially crafted graphics file such as a metafile (WMF/EMF). It affects both desktop and server environments, and in some cases **does not require user interaction**.

    [:octicons-arrow-right-24: View Full Details](Week47/ms-gfx.md)

-   ![Google Chrome V8 Zero-Day](Week47/images/chrome-v8.png)
    :material-google:{ .lg .middle } **Critical Google Chrome V8 Engine Zero-Day (CVE-2025-13223)**

    **Remote Code Execution**{.cve-chip}  
    **CVSS 9.8 Critical**{.cve-chip}  
    ---------------------------------

    A **zero-day vulnerability** in Google Chrome’s V8 JavaScript engine allows **remote attackers** to execute arbitrary code on affected systems. The flaw is triggered by **maliciously crafted web content** that can bypass Chrome’s security mechanisms. Exploitation can lead to **full compromise of the browser process**, potentially allowing attackers to execute code in the context of the logged-in user.  

    Users should **update Chrome immediately** to the latest patched version to mitigate the risk.

    [:octicons-arrow-right-24: View Full Details](Week47/chrome-v8.md)

-   ![IBM AIX NIM Vulnerabilities](Week47/images/aix.png)
    :material-server-security:{ .lg .middle } **Critical IBM AIX NIM Remote Code Execution (CVE-2025-36250)**

    **Remote Code Execution**{.cve-chip}
    **CVSS 10.0 Critical**{.cve-chip}
    ---------------------------------

    A critical vulnerability (CVE-2025-36250) in IBM AIX’s Network Installation Manager (NIM) allows **unauthenticated remote code execution** due to improper process controls in the *nimesis* service. Combined with related flaws (CVE-2025-36251, CVE-2025-36096, CVE-2025-36236), attackers can **execute commands remotely**, **steal NIM private keys**, and **write arbitrary files via directory traversal**, enabling full compromise of AIX and VIOS systems.
    Immediate patching of all AIX/VIOS installations and rotation of NIM keys is critical to prevent exploitation.

    [:octicons-arrow-right-24: View Full Details](Week47/aix.md)

-   ![D-Link DIR-816L Buffer Overflow](Week47/images/dlink.png)
    :material-alert-decagram:{ .lg .middle } **D-Link DIR-816L Stack-Based Buffer Overflow (CVE-2025-13189)**

    **Stack Buffer Overflow**{.cve-chip}  
    **High Severity**{.cve-chip}
    --------------------------------

    A high-severity vulnerability (CVE-2025-13189) in the D-Link DIR-816L router allows remote attackers to trigger a **stack-based buffer overflow** via crafted `SERVER_ID` or `HTTP_SID` parameters in the `gena.cgi` script. Exploitation can lead to **remote code execution**, device takeover, or denial-of-service. The router is **end-of-life**, and **no security patch will be released**.

    [:octicons-arrow-right-24: View Full Details](Week47/dlink.md)

-   ![Fortinet FortiWeb Authentication Bypass](Week47/images/fortiweb.png)
    :material-shield-lock:{ .lg .middle } **Fortinet FortiWeb Authentication Bypass (CVE-2025-64446)**

    **Authentication Bypass**{.cve-chip}
    **Critical Severity**{.cve-chip}
    --------------------------------

    A critical authentication bypass vulnerability (CVE-2025-64446) in Fortinet FortiWeb is being actively exploited in the wild. Attackers abuse a path traversal flaw and a crafted CGIINFO header to impersonate the built-in admin account, create rogue administrator users, and gain persistent full control over the Web Application Firewall (WAF). Immediate patching is mandatory to prevent compromise of network perimeter defenses.

    [:octicons-arrow-right-24: View Full Details](Week47/fortiweb.md)
    
</div>
