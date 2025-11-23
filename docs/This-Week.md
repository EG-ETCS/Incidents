---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![ABB Ability Edgenius](Week48/images/abb.png)
    :material-factory:{ .lg .middle } **Critical ABB Ability Edgenius Authentication Bypass (CVE-2025-10571)**

    **Authentication Bypass**{.cve-chip}  
    **Adjacent Network Access**{.cve-chip}  
    ---------------------------------

    CVE-2025-10571 is a critical authentication bypass vulnerability in ABB Ability Edgenius, an industrial edge computing and management platform. Due to improper access controls, an attacker on the adjacent network can directly interact with the Edgenius Management Portal and execute privileged operations without authentication. This allows attackers to install, modify, or uninstall software packages, reconfigure systems, or take control of edge nodes within an industrial environment.

    [:octicons-arrow-right-24: View Full Details](Week48/abb.md)

-   ![Oracle Identity Manager](Week48/images/oracle.png)
    :material-shield-lock:{ .lg .middle } **Critical Oracle Identity Manager Authentication Bypass (CVE-2025-61757)**

    **Authentication Bypass**{.cve-chip}  
    **Network Attack Vector**{.cve-chip}  
    ---------------------------------

    CVE-2025-61757 is a critical authentication bypass vulnerability in Oracle Identity Manager (OIM) REST WebServices, part of Oracle Fusion Middleware. Due to a logic flaw, certain sensitive API endpoints can be accessed without authentication, allowing attackers to invoke privileged identity management functions over the network. Because OIM controls the authentication and provisioning of enterprise accounts, exploitation can result in complete identity takeover across the environment.

    [:octicons-arrow-right-24: View Full Details](Week48/oracle.md)
    
</div>
