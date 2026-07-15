---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![SonicWall](2026/Week28/images/SonicWall.png)

    **SonicWall SMA urgent zero-day patch warning**

    **CVE-2025-23006**{.cve-chip} **CVE-2025-40602**{.cve-chip} **SMA 1000**{.cve-chip} **Zero-Day Chain**{.cve-chip} **Root RCE**{.cve-chip}

    SonicWall confirmed active in-the-wild chaining of CVE-2025-23006 and CVE-2025-40602 against SMA 1000 appliances, enabling unauthenticated remote compromise followed by root-level control through AMC/CMC management paths.

    [Read more](2026/Week28/SonicWall.md)

-   ![SAP](2026/Week28/images/SAP.png)

    **SAP NetWeaver ABAP CVE-2026-44747 (CVSS 9.9)**

    **CVE-2026-44747**{.cve-chip} **ABAP Platform**{.cve-chip} **Out-of-Bounds Write**{.cve-chip} **Memory Corruption**{.cve-chip} **Critical Patch**{.cve-chip}

    SAP's July 2026 updates fix CVE-2026-44747, a critical authenticated memory-corruption flaw in NetWeaver AS ABAP that can enable unauthorized data access/modification and potential denial of service, with additional high-severity SAP issues in the same patch cycle increasing enterprise urgency.

    [Read more](2026/Week28/SAP.md)

-   ![U-Boot](2026/Week28/images/U-Boot.png)   

    **Critical U-Boot Secure Boot Vulnerabilities (FIT Image Verification Flaws)**

    **Firmware Security**{.cve-chip} **U-Boot**{.cve-chip} **FIT Parser**{.cve-chip} **Secure Boot Bypass**{.cve-chip} **Pre-OS RCE Risk**{.cve-chip}

    Six newly disclosed U-Boot FIT verification flaws can be triggered before Secure Boot validation completes, enabling trusted-boot bypass and potential bootloader-level code execution that compromises devices before OS startup.

    [Read more](2026/Week28/U-Boot.md)

-   ![CMS](2026/Week28/images/CMS.png)   

    **Global Campaign Targeting Vulnerable CMS Platforms with Webshell Deployment**

    **Webshell Deployment**{.cve-chip} **Known CVE Exploitation**{.cve-chip} **CMS Platforms**{.cve-chip} **Persistence**{.cve-chip} **ACSC Alert**{.cve-chip}

    ACSC warns of a global campaign exploiting known but unpatched CMS and plugin flaws to implant webshells, establish persistent access, and enable credential theft, data exfiltration, ransomware deployment, and broader follow-on compromise.

    [Read more](2026/Week28/CMS.md)

-   ![Microsoft](2026/Week28/images/Microsoft.png)  

    **Fake Microsoft Entra Passkey Enrollment Vishing Campaign**

    **Vishing**{.cve-chip} **Microsoft Entra**{.cve-chip} **Passkey Abuse**{.cve-chip} **FIDO2/WebAuthn**{.cve-chip} **Account Persistence**{.cve-chip}

    Threat actor O-UNC-066 impersonates Microsoft or IT support to trick users into fake passkey enrollment, then registers attacker-controlled FIDO2/WebAuthn credentials for persistent unauthorized Microsoft 365 access even after password changes.

    [Read more](2026/Week28/Microsoft.md)

</div>
