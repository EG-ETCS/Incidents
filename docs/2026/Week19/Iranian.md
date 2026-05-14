# Iranian Hackers Targeted Major South Korean Electronics Maker
![alt text](images/Iranian.png)

**Seedworm / MuddyWater**{.cve-chip} **Iran-Linked APT**{.cve-chip} **DLL Sideloading**{.cve-chip} **Cyber Espionage**{.cve-chip}

## Overview

An Iran-linked threat group, Seedworm / MuddyWater (aka Static Kitten), operated by Iran's Ministry of Intelligence and Security (MOIS), ran a global cyber-espionage campaign in early 2026 that breached at least nine organizations across nine countries. Confirmed victims include a major South Korean electronics manufacturer, government agencies, an international airport in the Middle East, Southeast Asian industrial manufacturers, a Latin American financial-services provider, and universities.

The attackers used DLL sideloading with signed Fortemedia and SentinelOne binaries, Node.js-based implants, and PowerShell scripts for stealthy persistence, credential theft, and data exfiltration via the public file-transfer service sendit.sh. At the South Korean electronics firm, Seedworm maintained access for approximately one week in February 2026 before detection. Broadcom classifies the campaign as medium severity at the incident level but high in strategic terms, given its multi-sector, multi-region scope and the long-term intelligence value of stolen data.

## Technical Specifications

| Attribute | Details |
|---|---|
| **Threat Actor** | Seedworm / MuddyWater / Static Kitten (Iranian MOIS-sponsored APT) |
| **Campaign Period** | Early 2026 (South Korean victim: ~one week in February 2026) |
| **Victims** | 9+ organizations across 9 countries (electronics, government, aviation, industrial, financial, education) |
| **Initial Access** | Spear-phishing, weak VPN/RDP credentials |
| **Persistence Mechanism** | DLL sideloading via signed Fortemedia / SentinelOne binaries + Node.js implant |
| **C2 Communication** | Node.js-based backdoor communicating with attacker-controlled C2 servers |
| **Exfiltration Channel** | sendit.sh (public file-transfer service) over HTTPS to blend with normal SaaS traffic |
| **Post-Access TTPs** | PowerShell recon, LSASS credential dumping, AD enumeration, lateral movement |
| **CVE** | None — living-off-the-land and DLL sideloading; no specific vulnerability exploited |
| **Motivation** | Long-term espionage and intelligence collection |

## Affected Products

- **Windows endpoints** at victim organizations — DLL sideloading targets signed Fortemedia and SentinelOne executables present in the environment
- **Active Directory environments** — targeted for credential dumping and domain-wide lateral movement
- **Sectors targeted**: electronics manufacturing, government, aviation (international airport), industrial manufacturing, financial services, higher education

## Attack Scenario

1. **Initial compromise** — Seedworm delivers spear-phishing emails or exploits weak VPN/RDP credentials to obtain an initial foothold on a Windows system at the target organization
2. **DLL sideloading for stealthy persistence** — attackers drop a legitimately signed Fortemedia or SentinelOne executable alongside a trojanized DLL in the same directory; when the signed binary runs (or is made to run via a service or scheduled task), it sideloads the malicious DLL, which deploys a Node.js implant and establishes persistence — malicious processes appear as trusted software, evading application whitelisting and AV heuristics
3. **Reconnaissance and credential theft** — using PowerShell and built-in Windows LOLBins, attackers enumerate the domain (hosts, users, groups, AD structure), dump credentials from LSASS and cached stores, and access privileged admin accounts
4. **Lateral movement** — stolen credentials enable movement to file servers and systems holding intellectual property, product designs, internal communications, and business data
5. **Data staging and exfiltration** — valuable documents are staged and archived, then uploaded to sendit.sh via the Node.js implant over HTTPS, blending exfiltration traffic with normal cloud/SaaS activity and evading network-layer DLP
6. **Global parallel operations** — identical TTPs run concurrently against government agencies, an international Middle Eastern airport, Southeast Asian manufacturers, a Latin American financial firm, and universities across nine countries, forming a coordinated global espionage campaign

## Impact

=== "South Korean Electronics Maker"

    - **Confidentiality loss**: theft of internal documents, intellectual property, product designs, and strategic plans usable for intelligence gathering, industrial competitive advantage, or enabling future operations
    - **Credential compromise**: stolen credentials enable re-entry even after initial containment and can be leveraged against partners, subsidiaries, and supply-chain connections
    - Approximately one week of dwell time in February 2026 before detection

=== "Global Campaign Impact"

    - Government agencies and an international airport face sensitive information exposure with potential national security and operational resilience implications
    - Financial-services and industrial manufacturing victims risk business disruption, regulatory consequences, and further supply-chain compromise
    - Educational institutions targeted for research data and credential harvesting for follow-on operations

=== "Strategic Implications"

    - Confirms Iranian state actors are running multi-region espionage campaigns well beyond the Middle East, extending into East Asia, Latin America, and Western government and academic sectors
    - The use of signed binaries for sideloading and public cloud services (sendit.sh) for exfiltration reflects maturing tradecraft designed to blend in with legitimate activity and persist under defenders' radar
    - Broadcom assesses the campaign as **high** in strategic severity due to its multi-sector scope and the long-term intelligence value of stolen data across nine countries

## Mitigations

### Endpoint and Application Control

- **Monitor for DLL sideloading patterns** — alert on unsigned or unexpected DLLs loaded by known-signed binaries such as Fortemedia and SentinelOne executables; use EDR rules to flag processes with unusual DLL load paths
- **Restrict execution of unapproved binaries and DLLs** via application control policies; prevent binaries and DLLs dropped to non-standard paths (temp, user-writable directories) from executing
- **Detect Node.js implant abuse** — alert on Node.js processes running as system services or launched from unexpected paths, particularly on servers and endpoints that do not normally run Node.js workloads

### PowerShell and Script Security

- **Enable PowerShell Script Block Logging and Module Logging** centrally to capture recon and credential-theft scripts in telemetry
- **Apply PowerShell Constrained Language Mode** where operationally feasible to reduce the attack surface available to script-based TTPs
- **Alert on Seedworm-linked TTPs**: LSASS access and dumping (T1003.001), AD enumeration commands, creation of new services or scheduled tasks outside approved change windows

### Network Monitoring and Exfiltration Controls

- **Monitor and restrict access to public file-transfer services** (sendit.sh and similar) from sensitive networks — consider blocking such domains at the proxy/firewall level on systems handling intellectual property or sensitive data
- **Deploy DNS/HTTP proxying and DLP** to detect large or anomalous HTTPS uploads to cloud/SaaS file-sharing destinations
- **Baseline and alert on abnormal outbound data volumes** from servers and workstations in high-value segments

### Identity and Access Management

- **Enforce MFA on all remote access** (VPN, RDP) and key internal applications to reduce the value of stolen credentials for initial access
- **Regularly rotate privileged credentials** and monitor for anomalous logins, new admin account creation, and credential use from unusual source IPs or times

### Threat Hunting and Incident Response

- **Hunt proactively for Seedworm campaign indicators**: hashes and filenames of trojanized Fortemedia/SentinelOne DLLs, Node.js implant artifacts, sendit.sh upload activity in proxy logs
- **If suspicious activity is found, assume wider domain compromise** — scope the investigation to cover lateral movement paths, all domain credentials, and potential data exfiltration; involve IR teams early
- **Consider third-party notification** where stolen data may affect partners, subsidiaries, or supply-chain connections

## Resources

!!! info "Open-Source Reporting"
    - [Iran-Linked Hackers Breached Major Korean Electronics Maker in Global Espionage Campaign — Broadcom Security Center](https://www.broadcom.com/support/security-center/protection-bulletin/iran-linked-hackers-breached-major-korean-electronics-maker-in-global-espionage-campaign)
    - [Iran Seedworm Electronics Campaign — security.com Threat Intelligence](https://www.security.com/threat-intelligence/iran-seedworm-electronics)
    - [VivekIntel Campaign Thread — X (Twitter)](https://x.com/VivekIntel/status/2054684091963015444)

---

*Last Updated: May 14, 2026*