---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![Russian](2026/Week29/images/Russian.png)

    **Russian Intelligence Campaign Targeting Internet-Connected IP Cameras for Military Espionage**

    **Russian Espionage**{.cve-chip} **IP Camera Compromise**{.cve-chip} **Military Logistics Surveillance**{.cve-chip} **IoT Exposure**{.cve-chip} **OPSEC Risk**{.cve-chip}

    Dutch intelligence warns Russian actors are compromising internet-exposed IP cameras near military-relevant logistics routes across Europe to monitor troop and equipment movement, using weak credentials, exposed services, and unpatched firmware rather than direct military-network intrusion.

    [Read more](2026/Week29/Russian.md)

-   ![Gemini](2026/Week29/images/Gemini.png)

    **Russian-Speaking Threat Actor Uses Google Gemini CLI to Operate Botnet Infrastructure**

    **AI-Assisted Operations**{.cve-chip} **Botnet Management**{.cve-chip} **Gemini CLI Abuse**{.cve-chip} **Cloudflare Tunnel**{.cve-chip} **PowerShell Tradecraft**{.cve-chip}

    Trend Micro reported a Russian-speaking actor using Gemini CLI across roughly 200 sessions to deploy, troubleshoot, and migrate botnet infrastructure, accelerating C2 operations and endpoint command execution through AI-generated administrative workflows.

    [Read more](2026/Week29/Gemini.md)

-   ![WP2Shell](2026/Week29/images/WP2Shell.png)

    **WP2Shell WordPress Vulnerabilities Exploited in the Wild**

    **CVE-2026-63030**{.cve-chip} **CVE-2026-60137**{.cve-chip} **Pre-Auth RCE**{.cve-chip} **WordPress Core**{.cve-chip} **Active Exploitation**{.cve-chip}

    Attackers are actively chaining two WordPress core flaws to achieve anonymous pre-auth remote code execution on default vulnerable installations, with public PoCs available and post-exploitation activity including rogue admin creation and web shell deployment.

    [Read more](2026/Week29/WP2Shell.md)

-   ![SonicWall](2026/Week29/images/SonicWall.png)

    **SonicWall SMA 1000 SSRF + post-auth code-injection zero-days**

    **CVE-2026-15409**{.cve-chip} **CVE-2026-15410**{.cve-chip} **SMA 1000**{.cve-chip} **Zero-Day Chain**{.cve-chip} **Root RCE**{.cve-chip}

    SonicWall disclosed active exploitation of two SMA 1000 zero-days where CVE-2026-15409 (SSRF) can be chained with CVE-2026-15410 (post-auth code injection) to achieve effective unauthenticated root-level code execution on remote-access gateways.

    [Read more](2026/Week29/SonicWall.md)


-   ![Roaming](2026/Week29/images/Roaming.png)   

    **Iranian Mobile Tracking Campaign Targeting U.S. Military Personnel via SS7 Roaming and AdTech Data**

    **SS7 Abuse**{.cve-chip} **AdTech Data Correlation**{.cve-chip} **Location Intelligence**{.cve-chip} **OPSEC Risk**{.cve-chip} **Telecom Signaling**{.cve-chip}

    Iranian-linked actors reportedly combined SS7 roaming query abuse with commercial AdTech location data correlation to map movement patterns of U.S. military personnel and contractors in the Gulf, creating significant operational security and force-protection risk.

    [Read more](2026/Week29/Roaming.md)

-   ![Vacuum](2026/Week29/images/Vacuum.png)   

    **Unpatched Shark Robot Vacuum AWS IoT Authorization Vulnerability**

    **IoT Cloud Misconfiguration**{.cve-chip} **AWS IoT Core**{.cve-chip} **Certificate Abuse**{.cve-chip} **Cross-Device Access**{.cve-chip} **Privacy Exposure**{.cve-chip}

    Researchers found that extracting one Shark vacuum's AWS IoT certificate and key can enable unauthorized cross-device access in the same AWS region due to permissive cloud authorization policy, exposing map data, credentials, telemetry, and remote-control functions.

    [Read more](2026/Week29/Vacuum.md)

-   ![PhantomEnigma](2026/Week29/images/PhantomEnigma.png)   

    **PhantomEnigma Malware Campaign Leveraging Hijacked Brazilian Government Websites**

    **Supply-Chain Style Delivery**{.cve-chip} **Government Site Hijack**{.cve-chip} **Node.js Backdoor**{.cve-chip} **Trojanized Installers**{.cve-chip} **C2-Controlled Modules**{.cve-chip}

    Attackers compromised more than 20 Brazilian government websites and replaced legitimate software downloads with trojanized installers that deploy a modular Node.js backdoor, enabling persistent remote command execution and follow-on payload delivery.

    [Read more](2026/Week29/PhantomEnigma.md)

-   ![7-Zip](2026/Week29/images/7-Zip.png)   

    **7-Zip Remote Code Execution Vulnerability (CVE-2026-14266)**

    **CVE-2026-14266**{.cve-chip} **7-Zip**{.cve-chip} **Heap Overflow**{.cve-chip} **XZ Archive Parsing**{.cve-chip} **RCE Risk**{.cve-chip}

    A heap-based buffer overflow in 7-Zip's XZ archive processing can enable arbitrary code execution when victims open malicious archives with vulnerable versions prior to 26.02.

    [Read more](2026/Week29/7-Zip.md)

</div>
