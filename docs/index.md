---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![La Poste Cyberattack](Week52/images/laposte.png)
    :material-email-fast:{ .lg .middle } **Cyberattack on La Poste and La Banque Postale**

    **DDoS Attack**{.cve-chip}  
    **Critical Infrastructure**{.cve-chip}  
    **Banking Services**{.cve-chip}  
    **No Data Breach**{.cve-chip}  
    ---------------------------------

    **La Poste** (France's national postal service) and **La Banque Postale** suffered **DDoS cyberattack** disrupting **online and mobile services**. High-volume traffic flooding rendered **postal tracking**, **online banking portals**, **mobile apps**, and **digital identity services** unavailable. **Core banking systems and payment infrastructure remained operational**. **No data breach confirmed**—no malware, data exfiltration, or internal system compromise detected. Physical operations continued with increased branch/call center load. Services gradually restored via **DDoS scrubbing**, rate limiting, traffic rerouting. Strengthen DDoS protection (ISP/cloud-based), improve redundancy, enhance monitoring, stress-test services, and coordinate with ANSSI. Critical infrastructure availability attack.

    [:octicons-arrow-right-24: View Full Details](Week52/laposte.md)

-   ![n8n RCE Vulnerability](Week52/images/n8n.png)
    :material-robot-confused:{ .lg .middle } **CVE-2025-68613 n8n Critical RCE Vulnerability**

    **Remote Code Execution**{.cve-chip}  
    **CVSS 9.9**{.cve-chip}  
    **103,000+ Instances**{.cve-chip}  
    **Authenticated**{.cve-chip}  
    ---------------------------------

    **CVE-2025-68613** critical RCE in **n8n workflow automation platform** allows **authenticated attackers** to execute arbitrary code. **Insufficient sandboxing** of user-supplied workflow expressions enables **sandbox escape** accessing Node.js internal objects (`process`, `require`, `child_process`). Attacker with workflow permissions crafts malicious expression executing **system-level commands** with n8n process privileges. Affects **v0.211.0-v1.120.3** and **v1.121.0** (pre-patch). **~103,000+ exposed instances** globally. Enables **full system compromise**, **credential theft** (API keys, OAuth tokens), **workflow manipulation**, and **lateral movement**. **Upgrade to v1.120.4, v1.121.1, or v1.122.0**, restrict workflow permissions to trusted admins, enforce MFA, run with minimal OS privileges, and monitor for suspicious expressions.

    [:octicons-arrow-right-24: View Full Details](Week52/n8n.md)

</div>
