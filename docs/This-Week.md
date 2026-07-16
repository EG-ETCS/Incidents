---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![KFC](2026/Week28/images/KFC.png)

    **Cyberattack on Nichirei Logistics Disrupting KFC Japan and Food Supply Chain**

    **Supply Chain Cyberattack**{.cve-chip} **Third-Party Risk**{.cve-chip} **Cold-Chain Logistics**{.cve-chip} **Operational Disruption**{.cve-chip} **Food Sector Impact**{.cve-chip}

    A cyberattack on Nichirei disrupted frozen and refrigerated food distribution across Japan, affecting KFC Japan and other downstream organizations. Confirmed unauthorized access and logistics-system failures triggered shortages, delivery suspension, and service disruption across restaurants and related sectors.

    [Read more](2026/Week28/KFC.md)

-   ![Zoom](2026/Week28/images/Zoom.png)

    **Zoom Critical Account Takeover Vulnerability (CVE-2026-53412)**

    **CVE-2026-53412**{.cve-chip} **Account Takeover**{.cve-chip} **Improper Input Validation**{.cve-chip} **Zoom Windows Clients**{.cve-chip} **Critical Patch**{.cve-chip}

    Zoom disclosed CVE-2026-53412 (CVSS 9.8), a critical improper input validation flaw in Windows Zoom clients and SDK components that could allow unauthenticated remote account takeover. Zoom released fixes and recommends immediate patching; no active exploitation was publicly confirmed at disclosure.

    [Read more](2026/Week28/Zoom.md)

-   ![Russian](2026/Week28/images/Russian.png)

    **US and allies warn of Russian APT groups targeting routers and network devices**

    **Russian State-Sponsored Activity**{.cve-chip} **Network Infrastructure Targeting**{.cve-chip} **Credential Abuse**{.cve-chip} **Router Hygiene**{.cve-chip} **Critical Infrastructure Risk**{.cve-chip}

    NSA, CISA, FBI, and allied agencies warn that FSB-linked actors are compromising internet-exposed routers and network appliances using weak/default credentials, known patched flaws, and legacy protocols, then stealing configuration data and VPN secrets for persistent espionage footholds.

    [Read more](2026/Week28/Russian.md)

-   ![Cursor](2026/Week28/images/Cursor.png)

    **Unpatched Cursor IDE Local Git Executable Vulnerability**

    **Cursor IDE**{.cve-chip} **Local Executable Hijack**{.cve-chip} **Arbitrary Code Execution**{.cve-chip} **Windows Developers**{.cve-chip} **Supply Chain Risk**{.cve-chip}

    A Windows Cursor vulnerability allows attacker-controlled repositories to execute a local trojanized `git.exe` from the project directory instead of trusted system Git, enabling code execution on developer workstations and increasing software supply-chain compromise risk.

    [Read more](2026/Week28/Cursor.md)

-   ![AsyncAPI](2026/Week28/images/AsyncAPI.png)

    **AsyncAPI npm Supply Chain Attack**

    **Supply Chain Compromise**{.cve-chip} **npm Packages**{.cve-chip} **CI/CD Abuse**{.cve-chip} **GitHub Actions**{.cve-chip} **Miasma RAT**{.cve-chip}

    Attackers abused an unsafe GitHub Actions workflow to hijack AsyncAPI release automation and publish malicious code in legitimate npm packages, exposing developer systems and CI/CD pipelines to RAT delivery and credential theft at significant ecosystem scale.

    [Read more](2026/Week28/AsyncAPI.md)

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
