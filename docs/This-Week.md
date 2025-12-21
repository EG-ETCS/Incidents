---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![Tenda AC18](Week52/images/ac18.png)
    :material-router-wireless:{ .lg .middle } **CVE-2025-14993 Tenda AC18 Router Stack Overflow**

    **Stack-Based Buffer Overflow**{.cve-chip}  
    **Remote Code Execution**{.cve-chip}  
    **Denial of Service**{.cve-chip}  
    ---------------------------------

    Stack-based buffer overflow in Tenda AC18 router firmware **v15.03.05.05** affects `/goform/SetDlnaCfg` HTTP handler. **Insufficient input validation** allows remote attackers to send **crafted HTTP requests** triggering stack overflow. No authentication required if admin interface exposed. Improper bounds checking in **sprintf-like logic** overwrites stack memory (CWE-121). Enables **DoS via service crash** or **arbitrary code execution** with HTTP daemon privileges. Full **router compromise** allows traffic interception, DNS hijacking, and **lateral movement** to internal networks. **Disable WAN admin access**, update firmware, restrict interface access, and monitor `/goform/*` endpoints. Perimeter device vulnerability.

    [:octicons-arrow-right-24: View Full Details](Week52/ac18.md)

-   ![WatchGuard Firebox](Week52/images/watchguard.png)
    :material-fire:{ .lg .middle } **CVE-2025-14733 WatchGuard Firebox IKEv2 Zero-Day**

    **Out-of-Bounds Write**{.cve-chip}  
    **Remote Code Execution**{.cve-chip}  
    **Actively Exploited**{.cve-chip}  
    ---------------------------------

    Critical memory corruption in WatchGuard Fireware OS **iked process** enables **unauthenticated remote attackers** to execute arbitrary code via crafted **IKEv2 packets**. **Actively exploited in the wild**. Affects Mobile User VPN and Branch Office VPN with **dynamic gateway peers**. Out-of-bounds write (CWE-787) in IKEv2 handling causes memory corruption leading to **firewall compromise**. Enables VPN traffic interception, credential theft, and **lateral movement**. **Patch Fireware OS immediately**, disable IKEv2 dynamic peers if not needed, restrict VPN access, and monitor for exploitation. Perimeter breach risk.

    [:octicons-arrow-right-24: View Full Details](Week52/watchguard.md)

</div>
