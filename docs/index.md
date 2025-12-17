---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![Russian GRU Campaign](Week51/images/RussianGRU.png)
    :material-shield-alert:{ .lg .middle } **Russian GRU Cyber Campaign Targeting Critical Infrastructure**

    **Russian GRU**{.cve-chip}  
    **State-Sponsored**{.cve-chip}  
    **Edge Device Targeting**{.cve-chip}  
    ---------------------------------

    Multi-year **Russian military intelligence (GRU)** campaign targeting Western critical infrastructure via **misconfigured network edge devices**. Tactical evolution from vulnerability exploitation (2021-2024) to sustained focus on **misconfigurations in routers, VPN gateways, and network appliances** (2025). Uses **passive packet capture for credential harvesting** and **replay attacks** against cloud and energy sectors. Exposed by Amazon Threat Intelligence. Linked to **Curly COMrades** and other GRU clusters. **Harden edge device configurations**, implement MFA, restrict management interfaces, and deploy continuous monitoring for state-sponsored threats.

    [:octicons-arrow-right-24: View Full Details](Week51/RussianGRU.md)

-   ![Fortinet FortiSandbox](Week51/images/sandbox.png)
    :material-shield-bug:{ .lg .middle } **CVE-2025-53949 Fortinet FortiSandbox OS Command Injection**

    **OS Command Injection**{.cve-chip}  
    **Remote Code Execution**{.cve-chip}  
    **Critical**{.cve-chip}  
    ---------------------------------

    Critical OS command injection in FortiSandbox `upload_vdi_file` endpoint. Authenticated attackers can inject malicious commands due to **improper input validation**, achieving **root-level code execution** on the appliance. Affects FortiSandbox **5.0.0-5.0.2, 4.4.0-4.4.7, and all 4.2/4.0 versions**. Compromises **security infrastructure**, disrupts malware analysis, and enables **lateral movement**. **Patch immediately** to FortiSandbox 5.0.3+, 4.4.8+. Restrict management access, implement MFA, and monitor for suspicious activity. CWE-78.

    [:octicons-arrow-right-24: View Full Details](Week51/sandbox.md)

</div>
