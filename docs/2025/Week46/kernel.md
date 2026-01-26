# Actively Exploited Windows Kernel Zero‑Day (CVE-2025-62215) and Critical Zero‑Click Bugs

## Versions Affected

* **Windows 10** (versions 21H2, 22H2)
* **Windows 11** (versions 22H2, 23H2, and 24H2)
* **Windows Server 2019** (Core and Desktop Experience)
* **Windows Server 2022** (Core and Desktop Experience)
* **Windows Server 2025 Preview Builds**

## Description

Microsoft’s November 2025 security update fixes over 60 vulnerabilities, including an actively exploited zero‑day in the Windows Kernel (CVE-2025-62215) and several critical zero‑click vulnerabilities in Windows components like GDI+ and Kerberos.

The kernel vulnerability allows attackers to gain elevated (SYSTEM) privileges on affected systems. The GDI+ vulnerability (CVE-2025-60724) enables remote code execution without user interaction through malicious metafiles. Another Kerberos privilege escalation flaw (CVE-2025-60704, “CheckSum”) affects enterprise authentication.

## Technical Details

| **CVE / Component**                                         | **Type**                  | **Impact / Notes**                                                                                                                                                 |
| ----------------------------------------------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **CVE-2025-62215** (Windows Kernel Privilege Escalation)    | Race‑condition in kernel  | Local privilege escalation to SYSTEM. Exploited in the wild prior to patch release. Requires local access.                                                         |
| **CVE-2025-60724** (GDI+ Remote Code Execution)             | RCE in GDI+ image parsing | Triggered by opening or rendering a malicious metafile; zero‑click possible in some contexts. CVSS ~9.8 (Critical). Attack surface: network/file upload/rendering. |
| **CVE-2025-60704** (Kerberos CheckSum Privilege Escalation) | Authentication logic flaw | Enables forging/impersonation of privileged accounts in AD. Affects domain environments and enterprise authentication.                                             |

### Details by vulnerability

**CVE-2025-62215 – Windows Kernel Privilege Escalation**

* Type: Race‑condition vulnerability in Windows Kernel.
* Impact: Local privilege escalation to SYSTEM.
* Exploited in the wild before patch release.
* Attack vector: Local — requires prior access to the system.

**CVE-2025-60724 – GDI+ Remote Code Execution**

* Type: Remote code execution (RCE) in GDI+ image parsing.
* Trigger: Opening or rendering a malicious metafile; zero‑click possible in certain contexts.
* Severity: High (Critical).
* Attack vector: Network or file upload interface.

**CVE-2025-60704 – Kerberos Privilege Escalation (“CheckSum”)**

* Type: Authentication logic flaw in Kerberos CheckSum validation.
* Impact: Allows impersonation of privileged users in Active Directory.
* Affects: Domain environments and enterprise networks.

## Attack Scenario

**Kernel Zero‑Day (CVE-2025-62215)**
An attacker who has gained initial access (via phishing, malware, or another vulnerability) runs a crafted local exploit to trigger a race‑condition in the Windows kernel, escalating privileges from a standard user to SYSTEM.

**GDI+ Zero‑Click RCE (CVE-2025-60724)**
An attacker sends or hosts a document/image containing a malicious metafile. When a vulnerable Windows component processes it (even without user interaction in some cases), arbitrary code executes with the current user’s privileges.

**Kerberos Privilege Escalation (CVE-2025-60704)**
Within an enterprise network, attackers exploit the flawed checksum validation to forge authentication tokens, impersonate domain accounts, and gain lateral movement or full domain admin access.

## Impact Assessment

=== "System Compromise"
* Full system compromise via local privilege escalation (CVE-2025-62215)
* Remote code execution and initial compromise (CVE-2025-60724)
* Domain‑wide compromise and account impersonation (CVE-2025-60704)
* Secondary impacts: data exfiltration, ransomware deployment, persistence, and lateral movement

## Mitigation Strategies

### :material-update: Immediate Patch Deployment

* Apply Microsoft’s November 2025 security updates across all Windows systems as a priority.

### :material-security-network: Restrict Privileged Access

* Limit administrator privileges and enforce least‑privilege access models.

### :material-monitor-dashboard: Monitor for Exploitation Indicators

* Watch for unusual privilege escalation events, unexpected SYSTEM process creations, suspicious Kerberos ticket activity, and GDI+/application crashes.

### :material-security-network: Network & Service Hardening

* Disable or restrict services that automatically render user‑supplied images/metafiles (file upload parsers, preview services).
* Block or closely inspect common file upload vectors.

### :material-security-network: Active Directory & Kerberos Hardening

* Review delegation, constrained delegation, and Kerberos settings.
* Follow Microsoft guidance for CVE‑2025‑60704 mitigation, including any recommended configuration changes and monitoring controls.

## Resources & References

!!! info "Official & Media Reports"
    - [Microsoft Patches Actively Exploited Windows Kernel Zero-Day - SecurityWeek](https://www.securityweek.com/microsoft-patches-actively-exploited-windows-kernel-zero-day/)
    - [Security Update Guide - Microsoft](https://msrc.microsoft.com/update-guide)
    - [CVE-2025-60724 - Security Update Guide - Microsoft - GDI+ Remote Code Execution Vulnerability](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2025-60724)
    - [CVE Record: CVE-2025-60724](https://www.cve.org/CVERecord?id=CVE-2025-60724)
    - [Patch Now: Microsoft Flags Zero-Day & Zero-Click Bugs](https://www.darkreading.com/vulnerabilities-threats/patch-now-microsoft-zero-day-critical-zero-click-bugs)

!!! danger "Critical"
Systems not patched remain at high risk of exploitation. Prioritize patching, monitoring, and access restriction.

!!! tip "Response Checklist"
1. Patch affected systems immediately.
2. Audit privileged accounts and recent privilege escalation events.
3. Inspect logs for signs of exploitation and unusual Kerberos activity.
4. Isolate suspected compromised hosts and perform forensic analysis.
