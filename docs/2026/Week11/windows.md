# Microsoft Windows 11 RRAS Remote Code Execution Vulnerability - Out-of-Band Hotpatch
![alt text](images/windows.png)

**Windows 11**{.cve-chip} **RRAS**{.cve-chip} **Remote Code Execution**{.cve-chip}

## Overview

Microsoft released an out-of-band (OOB) hotpatch update to remediate multiple vulnerabilities in Windows 11 Routing and Remote Access Service (RRAS) management tooling. The flaws could allow remote code execution if an administrator connects the management interface to a malicious RRAS server.

The fix was delivered through hotpatch update KB5084597, enabling supported enterprise systems to receive mitigation without requiring a reboot.

## Technical Specifications

| Field | Details |
|-------|---------|
| **Identifier** | CVE-2026-25172 |
| **CVSS Score** | 8.0 (High) |
| **Incident Type** | Multiple RCE vulnerabilities in management interface |
| **Affected Component** | Windows 11 RRAS management tools |
| **Attack Vector** | Administrator connection to malicious/impersonated RRAS server |
| **Potential Outcome** | Arbitrary code execution on admin workstation |
| **Patch Type** | Out-of-band hotpatch |
| **Update ID** | KB5084597 |

## Affected Products

- Windows 11 enterprise environments using RRAS management interfaces.
- Administrative workstations used to manage routing and VPN services.
- Systems eligible for Windows hotpatch deployment.

## Technical Details

- The vulnerability class impacts RRAS management interaction with remote RRAS servers.
- Improper handling of server responses may lead to memory corruption or unsafe processing paths.
- A malicious or spoofed server could return crafted data to trigger code execution on the administrator host.
- The OOB hotpatch addressed multiple CVEs:
    - CVE-2026-25172
    - CVE-2026-25173
    - CVE-2026-26111
- Remediation was shipped via KB5084597 for supported enterprise hotpatch channels.

## Attack Scenario

1. An administrator launches RRAS management tools on a Windows system.
2. The admin connects to a remote RRAS server for routine management.
3. An attacker controls or impersonates that RRAS endpoint.
4. The malicious service returns specially crafted protocol responses.
5. The vulnerable management tool processes the malicious data.
6. Arbitrary code executes on the administrator machine.

## Impact Assessment

=== "System and Access Impact"
    Successful exploitation can enable remote code execution on enterprise management systems and provide privileged footholds through compromised administrative workstations.

=== "Operational Impact"
    RRAS and related routing/VPN operations may be disrupted during compromise and response activities.

=== "Network and Business Risk"
    Attackers may leverage compromised admin systems for lateral movement, increasing incident response burden and potential downtime for network administration functions.

## Mitigation Strategies

- Install KB5084597 hotpatch immediately on eligible systems.
- Apply all current Windows security updates across managed endpoints.
- Restrict RRAS management connections to trusted and validated servers only.
- Monitor administrative hosts for unusual RRAS connections and suspicious process behavior.
- Enforce network segmentation and least-privilege access controls for management systems.

## Resources

!!! info "References"
    - [Microsoft releases Windows 11 OOB hotpatch to fix RRAS RCE flaw](https://www.bleepingcomputer.com/news/microsoft/microsoft-releases-windows-11-oob-hotpatch-to-fix-rras-rce-flaw/)
    - [March 13, 2026 - Hotpatch KB5084597 (OS Builds 26200.7982 and 26100.7982) Out-of-band - Microsoft Support](https://support.microsoft.com/en-us/topic/march-13-2026-hotpatch-kb5084597-os-builds-26200-7982-and-26100-7982-out-of-band-ef323fee-e70f-4f43-8bbc-1021c435bf5c)
    - [Windows 11 RRAS Hotpatch KB5084597: Restartless Fix for Remote Networking Risks | Windows Forum](https://windowsforum.com/threads/windows-11-rras-hotpatch-kb5084597-restartless-fix-for-remote-networking-risks.405115/)
    - [CVE-2026-25172 - Security Update Guide - Microsoft - Windows Routing and Remote Access Service (RRAS) Remote Code Execution Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-25172)

---

*Last Updated: March 15, 2026*