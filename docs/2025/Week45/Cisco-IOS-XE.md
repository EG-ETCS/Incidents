# Cisco IOS XE BADCANDY Web Shell Implant

**CVE-2023-20198**{.cve-chip}
**Remote full system compromise**{.cve-chip}
**Credential theft**{.cve-chip}

## Overview
BADCANDY is a malicious Lua-based web shell implant deployed by threat actors on vulnerable Cisco IOS XE devices. Attackers exploit the critical zero-day vulnerability CVE-2023-20198 in the web UI, leading to complete remote compromise of network infrastructure, including routers and switches widely used in enterprise and telecom environments.

## Technical Details

| **Attribute** | **Details** |
|---------------|-------------|
| **CVE ID** | CVE-2023-20198 |
| **Vulnerability Type** | Unauthenticated Privilege Escalation, Web Shell Implant |
| **Attack Vector** | Remote (web UI) |
| **Authentication** | None required |
| **Complexity** | Low |
| **User Interaction** | Not required |

### Exploit Method
- Remote, unauthenticated creation of level 15 (highest privilege) accounts via the web interface
- BADCANDY is a small, Lua-scripted web shell, granting attackers remote code execution and configuration control at the system or IOS level
- Not persistent (removed on reboot), but attackers commonly create privileged accounts or alternate implants for continued access
- After exploitation, a non-persistent patch is sometimes applied to mask vulnerability, making detection harder

## Attack Scenario
1. **Initial Access**: Attacker scans for unpatched Cisco IOS XE devices exposed to the internet
2. **Exploitation**: Using CVE-2023-20198, attackers create a privileged account via the web UI without authentication
3. **Payload Delivery**: Attacker installs BADCANDY web shell using the new admin account
4. **Command & Control**: BADCANDY implant provides a hidden endpoint for attackers to run arbitrary commands, create more backdoors, or extract credentials
5. **Concealment & Re-exploitation**: Non-persistent masking patch may be applied. If implant is removed or device rebooted, attacker can reinfect at will if device remains unpatched
6. **Persistence**: Privileged accounts or custom tunnels can persist after rebooting, even though BADCANDY itself does not

## Impact Assessment

=== "Integrity"
  * Unrestricted configuration changes
  * Creation of persistent privileged accounts
  * Network traffic interception or redirection

=== "Confidentiality"
  * Credential theft (administration and network credentials)
  * Extraction of sensitive configuration data

=== "Availability"
  * Device and network disruption
  * Repeated reinfection if unpatched

=== "Network Security"
  * Large-scale exploitation (over 400 devices in Australia alone as of October 2025)
  * Active campaigns targeting telecom, government, and infrastructure sectors
  * Sector-wide risk for any organization using vulnerable Cisco IOS XE devices

## Mitigation Strategies

### :material-update: Patch and Remediation
- **Patch ASAP**: Apply Cisco’s security update for CVE-2023-20198 and related vulnerabilities
- **Reboot**: Cleans BADCANDY but not attacker-created accounts or alternate backdoors
- **Configuration audit**: Remove unexpected privileged user accounts (e.g., `cisco_tac_admin`, `cisco_support`, `cisco_sys_manager`) and unknown tunnel interfaces

### :material-security-network: Access Controls
- **Restrict web UI**: Disable local HTTP server unless absolutely needed; limit device internet exposure
- **Review logs**: Inspect TACACS+ AAA command accounting logs and verify configuration/authentication changes

## Technical Recommendations

### Immediate Actions
1. **Patch all exposed Cisco IOS XE devices**
2. **Reboot devices to remove non-persistent implants**
3. **Audit configuration for unauthorized accounts and tunnels**
4. **Restrict or disable web UI access**
5. **Review logs for suspicious activity**

### Short-term Measures
1. **Network segmentation**: Isolate management interfaces
2. **Monitor for new privileged accounts**
3. **Incident response**: Prepare for rapid remediation if compromise is detected

### Long-term Strategy
1. **Ongoing patch management**
2. **Security architecture review**
3. **Staff training on device security**

## Resources

1. [Don’t take BADCANDY from strangers – How your devices could be implanted and what to do about it | Cyber.gov.au](https://www.cyber.gov.au)
2. [ASD Warns of Ongoing BADCANDY Attacks Exploiting Cisco IOS XE Vulnerability](https://www.cyber.gov.au)
3. [Multiple Vulnerabilities in Cisco IOS XE Software Web UI Feature](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-rce-3rdparty-6pP6aK)