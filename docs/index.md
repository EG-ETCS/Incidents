---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![React2Shell](Week50/images/react2shell.png)
    :material-react:{ .lg .middle } **React2Shell (CVE-2025-55182)**

    **Remote Code Execution**{.cve-chip}  
    **Unsafe Deserialization**{.cve-chip}  
    ---------------------------------

    Critical vulnerability in React Server Components (RSC) "Flight" protocol allowing **unauthenticated remote code execution** via unsafe deserialization. Affects react-server-dom-webpack/parcel/turbopack (versions 19.0-19.2.0) and Next.js. Single malicious HTTP request triggers arbitrary code execution on server. **Public PoC available, active exploitation confirmed** by multiple threat actors including state-linked groups. ~39% of cloud environments vulnerable. **Patch immediately** to React 19.0.1/19.1.2/19.2.1 or Next.js fixed versions.

    [:octicons-arrow-right-24: View Full Details](Week50/react2shell.md)

-   ![Johnson Controls](Week50/images/johnson.png)
    :material-office-building:{ .lg .middle } **Johnson Controls FX80 / FX90 Vulnerability (CVE-2025-43867)**

    **Configuration File Compromise**{.cve-chip}  
    **Building Automation**{.cve-chip}  
    ---------------------------------

    Vulnerability in Johnson Controls FX80 and FX90 building-automation controllers running FX14.10.10 or FX14.14.1. Attackers with network or local access could compromise device configuration files (read/write/tamper). Affects HVAC, climate control, and access control systems. Exploitation may trigger additional CVEs (CVE-2025-3936 through CVE-2025-3945). **Update to 14.10.11 or 14.14.2** to mitigate. Risk to critical infrastructure in commercial buildings and industrial facilities.

    [:octicons-arrow-right-24: View Full Details](Week50/johnson.md)

</div>
