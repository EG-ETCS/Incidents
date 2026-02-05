# RedKitten — Iran-Linked Cyber-Espionage Campaign

**Cyber-Espionage**{.cve-chip}  **Macro Malware**{.cve-chip}  **SloppyMIO Backdoor**{.cve-chip}

## Overview
RedKitten is an Iran-linked cyber-espionage campaign that uses weaponized Excel spreadsheets with malicious macros to install a backdoor called SloppyMIO on victim systems. The spreadsheets are crafted to appear as data about protesters or missing persons in Iran, exploiting emotional urgency to induce macro enabling and infection. The campaign targets civil society and human rights organizations, with roughly 50 victims identified so far.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Campaign Name** | RedKitten |
| **Threat Type** | Cyber-Espionage |
| **Initial Access** | Spear-phishing with 7-Zip archive containing XLSM |
| **User Interaction** | Required (enable macros) |
| **Malware** | SloppyMIO backdoor |
| **C2** | Telegram Bot API |
| **Data Exfiltration** | Yes |

## Affected Products
- Microsoft Excel (XLSM macro-enabled files)
- Windows endpoints running Office with macros enabled
- Civil society and human rights organizations
- Status: Active campaign

## Technical Details

### Infection Vector
- Spear-phishing email or message containing a 7-Zip archive named in Farsi
- Archive contains a macro-enabled XLSM Excel file
- When macros are enabled, VBA code drops a C# backdoor DLL (`AppVStreamingUX_Multi_User.dll`) using AppDomainManager injection

### Malware – SloppyMIO
- Fetches configuration steganographically embedded in images retrieved from GitHub and Google Drive
- Uses Telegram Bot API for command-and-control (C2)
- Supports multiple modules:
    - **cm**: run `cmd.exe` commands
    - **do**: collect, zip, and exfiltrate files
    - **up**: write files encoded in images to disk
    - **pr**: schedule persistence
    - **ra**: launch processes
- Beacons and polls Telegram for instructions

### AI Use
- VBA macro code exhibits signs of AI generation (style, naming, method usage)

## Attack Scenario
1. Target receives a spear-phishing email or message with a 7-Zip archive
2. Victim opens the Excel file and enables macros
3. The macro launches SloppyMIO via AppDomainManager injection
4. SloppyMIO phones back to C2 through Telegram Bot API
5. Operators execute commands, exfiltrate files, and establish persistence

## Impact Assessment

=== "Confidentiality"
    * Sensitive documents and communications are stolen
    * Credential theft and access to internal systems
    * Exposure of human rights workflows and sources

=== "Integrity"
    * Malicious code execution on victim endpoints
    * Potential manipulation of files and system settings
    * Persistence mechanisms alter system behavior

=== "Availability"
    * Potential service disruption on infected endpoints
    * Operational degradation due to persistent malware
    * Increased incident response overhead

## Mitigation Strategies

### Immediate Actions
- Block access to known malicious infrastructure (GitHub dead drops, Google Drive links, Telegram Bot API endpoints)
- Disable macros by default across the organization
- Quarantine and analyze suspicious 7-Zip archives and XLSM files
- Review endpoints for `AppVStreamingUX_Multi_User.dll` and AppDomainManager injection artifacts

### Short-term Measures
- User awareness training focused on phishing and social engineering
- Implement email security to block macro-enabled attachments
- Enforce strict macro policies (signed macros only)
- Harden Office settings to disable macros from the internet

### Monitoring & Detection
- Detect AppDomainManager injection events
- Monitor scheduled tasks and unusual DLLs in `%LOCALAPPDATA%`
- Monitor for outgoing connections to Telegram, GitHub, and Google Drive
- Alert on creation of new persistence mechanisms

### Long-term Solutions
- Implement endpoint detection and response (EDR) with macro abuse detections
- Segment networks to limit lateral movement from infected hosts
- Maintain threat intelligence feeds for RedKitten infrastructure
- Establish incident response playbooks for macro-based infections

## Resources and References

!!! info "Incident Reports"
    - [Iran-Linked RedKitten Cyber Campaign Targets Human Rights NGOs and Activists](https://thehackernews.com/2026/01/iran-linked-redkitten-cyber-campaign.html)
    - [Iran-Linked RedKitten Cyber Campaign Targets Human Rights NGOs and Activists - Live Threat Intelligence - Threat Radar | OffSeq.com](https://radar.offseq.com/threat/iran-linked-redkitten-cyber-campaign-targets-human-f0c3bff7)
    - [RedKitten APT Targets Microsoft Excel Vulnerabilities in Cyber-Espionage Campaign Against Iranian Human Rights NGOs and Activists](https://www.rescana.com/post/redkitten-apt-targets-microsoft-excel-vulnerabilities-in-cyber-espionage-campaign-against-iranian-hu)

---

*Last Updated: February 2, 2026* 