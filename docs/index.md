---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![canfail](2026/Week7/images/canfail.png)

    **Suspected Russian Hackers Deploy CANFAIL Malware Against Ukraine**

    **Russian-Linked**{.cve-chip} **Malware Loader**{.cve-chip} **Ukraine Targeting**{.cve-chip} **Espionage**{.cve-chip}

    Security researchers at Google Threat Intelligence identified a previously undocumented Russian-linked threat actor deploying CANFAIL, a new Windows malware loader, in phishing campaigns targeting Ukrainian defense, government, and energy organizations. The multi-stage infection chain uses obfuscated JavaScript files disguised as documents to deliver PowerShell-based payloads that operate entirely in-memory.

    The campaign focuses on espionage and long-term access to sensitive Ukrainian systems, avoiding immediate destruction. CANFAIL demonstrates sophisticated social engineering, in-memory execution to bypass antivirus detection, and potential for staged deployment of additional offensive tools against critical infrastructure.

    [:octicons-arrow-right-24: Read more](2026/Week7/canfail.md)

-   ![uat9921](2026/Week7/images/uat9921.png)

    **UAT-9921 Deploys VoidLink Malware to Target Technology and Financial Sectors**

    **VoidLink Malware**{.cve-chip} **Enterprise Espionage**{.cve-chip} **Linux Targeting**{.cve-chip} **Cloud Infrastructure**{.cve-chip}

    Threat researchers identified a newly discovered threat actor tracked as UAT-9921 deploying VoidLink, a sophisticated modular malware framework targeting Linux servers in technology and financial sectors. Described as "defense-contractor-grade," VoidLink combines Zig implants, C plugins, and Go backend services with advanced capabilities including kernel-level rootkits, mesh peer-to-peer C2 networks, and comprehensive EDR evasion.

    The framework employs modular plugin architecture for reconnaissance, lateral movement, privilege escalation, and data theft, with initial access typically via stolen credentials or Java deserialization vulnerabilities. VoidLink's mesh C2 architecture enables attackers to route traffic through compromised nodes, bypassing network segmentation and enabling prolonged undetected compromise of cloud and enterprise infrastructure.

    [:octicons-arrow-right-24: Read more](2026/Week7/uat9921.md)

</div>
