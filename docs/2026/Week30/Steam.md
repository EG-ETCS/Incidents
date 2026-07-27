# Steam Forum ClickFix XMRig Cryptominer Campaign
![alt text](images/Steam.png)

**ClickFix Social Engineering**{.cve-chip} **Steam Forum Abuse**{.cve-chip} **PowerShell Execution**{.cve-chip} **XMRig Cryptojacking**{.cve-chip} **Windows Persistence**{.cve-chip}

## Overview

Threat actors are posting fraudulent troubleshooting replies in Steam community discussion forums, specifically targeting users reporting crashes, lost inventory, or other game issues.

The replies instruct users to launch PowerShell as Administrator and run a command presented as a fix, but the command instead downloads and installs XMRig cryptominer malware on Windows endpoints.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Attack Type** | ClickFix-style social engineering campaign |
| **Primary Vector** | Malicious replies in Steam discussion forums (no Steam platform vulnerability reported) |
| **Initial User Action Required** | Victim runs attacker-provided PowerShell command as Administrator |
| **Script Masquerade** | Fake utility text such as `msf utility \ PC Opt.` with deceptive progress output |
| **Network/Security Manipulation** | Disables TLS certificate validation and creates temporary outbound firewall allowance to `msfconfig[.]icu` over TCP 443 |
| **Payload Delivery** | Downloads and executes XMRig miner components from attacker infrastructure |
| **Persistence Mechanism** | Scheduled task `XMRig-[computer name]` executes `system.exe` at startup with SYSTEM privileges |
| **Evasion Technique** | Creates `C:\Windows\Background` and adds Microsoft Defender exclusion for that path |
| **Post-Compromise Activity** | Maintains outbound firewall rules supporting mining communication |
| **Known Payload Scope** | No confirmed additional malware beyond cryptomining payload in current reporting |

## Affected Products

- Windows systems where users run attacker-provided PowerShell commands
- Steam community users exposed to malicious troubleshooting replies
- Potentially enterprise-managed endpoints if Steam is used on corporate devices
- Infrastructure and organizations exposed to endpoint resource drain from cryptojacking

## Attack Scenario

1. A gamer posts in Steam forums requesting technical help.
2. Threat actor account replies with a convincing troubleshooting command.
3. Victim is told to run PowerShell as Administrator and execute the script.
4. Script downloads XMRig payload from attacker-controlled infrastructure and deploys persistence.
5. Defender exclusions and firewall-rule changes reduce detection and enable mining traffic.
6. Miner runs at startup with SYSTEM privileges, consuming system resources for attacker profit.

## Impact Assessment

=== "Integrity"

    - Unauthorized scheduled tasks, firewall policy changes, and Defender exclusions alter host security posture
    - Administrative script execution allows broad system modification capability beyond mining intent
    - Attack workflow can be repurposed rapidly for more destructive payloads

=== "Confidentiality"

    - Current reporting does not confirm data theft in this campaign
    - However, SYSTEM-level script execution creates high potential exposure of local credentials and sensitive data
    - Compromised endpoints may provide footholds for follow-on credential access or lateral movement

=== "Availability"

    - Sustained CPU/GPU utilization causes degraded gameplay, lag, overheating risk, and higher power consumption
    - Endpoints may suffer reduced stability and shortened hardware lifespan under prolonged mining load
    - Enterprise devices can experience measurable resource drain and operational performance impact

## Mitigation Strategies

### User Behavior and Awareness

- Never execute PowerShell commands copied from unverified forum users, even if framed as urgent fixes
- Validate troubleshooting guidance through official game support channels or trusted maintainers
- Treat any command requiring Administrator rights from unknown sources as suspicious by default

### Detection and Cleanup for Affected Systems

- Check for suspicious scheduled tasks such as `XMRig-[computer name]`
- Inspect for unexpected Defender exclusions, including `C:\Windows\Background`
- Review Windows Firewall changes and outbound connections related to `msfconfig[.]icu`
- Remove malicious tasks/files, revert unauthorized policy changes, and run full endpoint malware scans

### Platform and Community Measures

- Increase moderation and automated detection of command-sharing abuse in forum replies
- Flag or temporarily suppress posts containing suspicious PowerShell one-liners
- Promote in-forum safety banners warning users not to run unknown administrative scripts

### Enterprise Controls

- Block or tightly constrain PowerShell execution on non-admin endpoints using policy controls
- Enforce endpoint detection rules for cryptominer behaviors and suspicious persistence artifacts
- Restrict local admin rights, monitor scheduled-task creation, and alert on Defender exclusion changes

## Resources and References

!!! info "Public Reporting"
    - [Steam forum ClickFix attacks infect gamers with XMRig cryptominers](https://www.bleepingcomputer.com/news/security/steam-forum-clickfix-attacks-infect-gamers-with-xmrig-cryptominers/)
    - [LinkedIn summary thread: Steam forum ClickFix attacks infect gamers](https://www.linkedin.com/posts/wayne-shaw-19a81a14_steam-forum-clickfix-attacks-infect-gamers-activity-7486925068367745024-l0wp)
    - [OffSec Radar entry: Steam forum ClickFix attacks](https://radar.offseq.com/threat/steam-forum-clickfix-attacks-infect-gamers-with-xmrig-cryptominers-867bfd77e7b3f987)
    - [XMRig malware overview (Check Point)](https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/xmrig-malware/)

---

*Last Updated: July 27, 2026*
