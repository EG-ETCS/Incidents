# MuddyWater MuddyViper Backdoor Campaign

**APT Campaign**{.cve-chip}  
**Iran-Aligned Threat Actor**{.cve-chip}  
**Espionage**{.cve-chip}

## Overview

MuddyWater — a long-standing Iran-aligned APT — launched a targeted espionage campaign against Israeli organizations and at least one Egyptian organization. The group deployed a new custom malware toolkit centered around **MuddyViper**, a backdoor previously undocumented publicly. The campaign combined spear-phishing, social engineering, and advanced loader/backdoor techniques to stealthily penetrate and persist within victim networks.

Instead of the group's older, noisier methods, this operation exhibited **technical sophistication** — memory-only loaders, covert credential and browser-data theft, reverse tunneling for data exfiltration, and evasion techniques. This represents a notable escalation of capability and tradecraft for MuddyWater.

## Technical Specifications

| **Attribute**           | **Details**                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| **Threat Actor**        | MuddyWater (Iran-aligned APT)                                               |
| **Target Region**       | Israel, Egypt                                                               |
| **Target Sectors**      | Critical infrastructure (utilities, manufacturing, government, transportation) |
| **Primary Malware**     | MuddyViper (backdoor), Fooder (loader)                                      |
| **Initial Access**      | Spear-phishing with RMM tool installers                                     |
| **Delivery Platform**   | OneHub, Egnyte, Mega (free file-sharing platforms)                          |
| **RMM Tools Used**      | Atera, PDQ, SimpleHelp                                                      |
| **Associated Group**    | Lyceum / OilRig (secondary access broker)                                   |

![](images/muddy1.png)

## Technical Details

### Fooder Loader
- Custom **64-bit loader**
- Decrypts and **reflectively loads MuddyViper directly into memory** (no disk drop)
- Helps evade disk-based detection mechanisms
- Several variants masquerade as the classic **"Snake" video game**
- Uses custom delay to avoid sandbox/automated analysis:
    - Mimics the game's logic
    - Repeated "Sleep" API calls

![](images/muddy2.png)

### MuddyViper Backdoor
- **C/C++-based backdoor**
- Capabilities include:
    - Collecting system information
    - Executing commands/files
    - Transferring files
    - Exfiltrating Windows login credentials and browser data
    - Reverse-tunnel (e.g., via socks5) for remote access/tunneling
    - Persistence mechanisms

![](images/muddy3.png)

### Additional Tools
- **CE-Notes**: Targets Chromium-based browsers
- **LP-Notes**: For credential staging/verification
- **Blub**: Steals login data from multiple browsers
- Additional utility tools for reverse tunnels

### Technical Sophistication
- Uses **Windows Cryptography API Next Generation (CNG)** for encryption/decryption
- Shows unusual sophistication and possibly indicates improved development resources
- Memory-only execution to evade detection

### Initial Access Vector
- Typically **spear-phishing emails**
- Often containing PDF attachments that link to installers for **Remote-Monitoring/Management (RMM) tools**
- RMM installers hosted on free file-sharing platforms (OneHub, Egnyte, Mega)
- Once RMM tools installed, the chain would ultimately deploy Fooder + MuddyViper

### Access Broker Activity
In some cases, **MuddyWater acted as an initial access broker**: after initial compromise, credentials or access were handed over to another Iran-aligned group, **Lyceum** (a subgroup of OilRig), which carried out further operations within the victim environment.

## Attack Scenario

1. **Spear-Phishing**: Recipient receives PDF or link to RMM installer hosted on free file-sharing site.

2. **RMM Installation**: Victim downloads & installs the RMM tool (e.g., Atera, PDQ, SimpleHelp, etc.).

3. **Loader Deployment**: Using the RMM foothold (or via separate loader), attackers drop the **Fooder loader**.

4. **Memory-Only Execution**: Fooder runs (disguised as Snake game), reflectively loads **MuddyViper into memory** — no disk drop — to evade detection.

5. **Persistence & C2**: MuddyViper establishes persistence, connects to C2 infrastructure, and provides remote control capabilities.

6. **Credential Theft**: Attackers deploy credential / browser-data stealers (CE-Notes, LP-Notes, Blub).

7. **Data Exfiltration**: Set up reverse tunnels or socks5 proxies to exfiltrate data.

8. **Access Handoff (in some cases)**: After initial compromise, credentials or access are passed to **Lyceum / OilRig** for further exploitation (e.g., in manufacturing-sector targets).

This chain demonstrates a move towards **stealth, persistence, and multi-staged, modular attacks**.

## Impact Assessment

=== "Remote Control & Access"
    * Full remote control of infected systems
    * Ability to execute arbitrary commands
    * Potentially pivot across networks
    * Escalate privileges
    * Exfiltrate sensitive data

=== "Credential Theft"
    * Theft of Windows login credentials + browser data (passwords, stored credentials)
    * Enabling further lateral movement, credential reuse, or access to other systems/accounts

=== "Data Exfiltration"
    * Data exfiltration back to attacker-controlled infrastructure
    * Via reverse tunnels / socks proxies
    * Could compromise sensitive corporate/government data, intellectual property, or personal data

=== "Persistence & Stealth"
    * Memory-only loading and stealth techniques make detection hard
    * Increasing the risk of **long-term compromise and sustained espionage**

=== "Critical Infrastructure Risk"
    * For organizations in affected sectors (especially critical infrastructure: utilities, manufacturing, government, transportation)
    * Compromise could threaten operational integrity, confidentiality, and business continuity
    * Risk to **national security and sensitive infrastructure** is substantial

## Mitigations

### 📧 Email Security & Phishing Defenses
- Strengthen email security & phishing defenses
- Tighten filtering, block or closely monitor attachments (PDFs linking to RMM installers)
- Enforce macro-blocking or sandboxing

### 🔐 Authentication
- Require **multi-factor authentication (MFA)** across all accounts
- Especially for RMM tools, remote access, high-privilege accounts

### 🛡️ Endpoint & Network Detection
- Use **behavior-based endpoint detection and response (EDR)** and **network detection & response (NDR)**
- Since memory-only loaders + in-memory backdoors evade traditional antivirus/sig-based detection

### 📊 Monitoring
- Monitor for:
    - Anomalous outbound connections
    - Reverse tunnels
    - Unusual remote-management software usage

### 🔧 RMM Tool Management
- **Limit or strictly manage** use of RMM / remote-management tools
- Treat them as high-risk
- Restrict to approved tools
- Monitor their installation & usage

### 🏗️ Network Architecture
- **Segmentation**, least-privilege principle, network egress filtering
- Limit ability of compromised endpoints to reach sensitive network segments or exfiltrate data

### 🔑 Credential Hygiene
- **Rotate credentials regularly**
- Monitor for abnormal login behavior
- Implement privilege separation & least privilege

### 🔍 Threat Hunting
- **Hunt for indicators of compromise (IOCs)** tied to known tools
- Track publicly released IOCs (hashes, domains, C2 infrastructure) linked to:
    - MuddyViper
    - Fooder
    - Credential stealers (CE-Notes / LP-Notes / Blub)

## Resources & References

!!! info "Research & Analysis"
    * [Iran's MuddyWater targets critical infrastructure in Israel and Egypt, masquerades as Snake game – ESET Research](https://www.welivesecurity.com/en/eset-research/)
    * [MuddyWater: Snakes by the riverbank](https://example.com)
    * [MuddyWater cyber campaign adds new backdoors in latest wave of attacks - Help Net Security](https://www.helpnetsecurity.com)
    * [Iran's 'MuddyWater' Levels Up With MuddyViper Backdoor](https://example.com)
    * [Iran-Linked Hackers Hit Israeli Sectors with New MuddyViper Backdoor in Targeted Attacks](https://example.com)
    * [Unmasking MuddyWater's New Malware Toolkit Driving International Espionage | Group-IB Blog](https://www.group-ib.com/blog/)