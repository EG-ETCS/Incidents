---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![Digiever NVR Vulnerability](Week53/images/digiever.png)

    **Digiever DS-2105 Pro NVR Authorization Bypass & Command Injection**

    **CVE-2023-52163**{.cve-chip} 
    **CVE-2023-52164**{.cve-chip} 
    **CVSS 9.8**{.cve-chip} 
    **CISA KEV**{.cve-chip} 
    **RCE**{.cve-chip}

    Critical vulnerability chain in end-of-life Digiever DS-2105 Pro Network Video Recorders allows unauthenticated attackers to bypass authorization and execute arbitrary OS commands via time_tzsetup.cgi endpoint. CISA confirms active exploitation by Mirai and ShadowV2 botnets. Attackers inject commands without authentication, deploy malware, hijack surveillance footage, harvest credentials via CVE-2023-52164 file read, and pivot to internal networks. No patches available (EoL device).

    [:octicons-arrow-right-24: View Full Details](Week53/digiever.md)

-   ![npm Phishing Campaign](Week53/images/npm.png)

    **Malicious npm Packages Abused as Phishing Infrastructure**

    **npm Supply Chain**{.cve-chip} 
    **Phishing Infrastructure**{.cve-chip} 
    **Credential Theft**{.cve-chip} 
    **CDN Abuse**{.cve-chip}

    Sophisticated phishing campaign published 27 malicious npm packages across 6 attacker accounts, abusing npm's CDN as hosting platform for phishing content. Packages hosted HTML/JS payloads (not functional code) mimicking document portals that redirected to fake Microsoft 365 login pages with pre-filled emails. Evilginx-style AitM framework bypasses traditional MFA via session token theft. Anti-analysis techniques include JavaScript obfuscation, bot detection, and user interaction validation. Healthcare and industrial sectors targeted for BEC and potential OT access.

    **Mitigation:** Deploy phishing-resistant MFA (FIDO2/WebAuthn). Implement Conditional Access policies. Use private npm registries with package allowlists. Monitor authentication logs for impossible travel and suspicious token activity. Train users on trusted-platform phishing tactics.

    [:octicons-arrow-right-24: View Full Details](Week53/npm.md)

</div>
