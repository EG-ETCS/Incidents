# Microsoft Edge Stores Passwords in Process Memory, Posing Enterprise Risk
![alt text](images/Edge.png)

**Microsoft Edge**{.cve-chip} **Credential Exposure**{.cve-chip} **Enterprise Risk**{.cve-chip} **Password Manager**{.cve-chip}

## Overview

Security researcher Lars Rønning (@L1v1ng0ffTh3L4N) discovered that Microsoft Edge decrypts every saved password from its local vault into process memory at browser startup, keeping them resident in plaintext for the entire session — regardless of whether the user visits any of those sites. Dark Reading reported in early May 2026 that this means any attacker who reaches local admin or SYSTEM-level access on an endpoint can dump Edge process memory and recover all stored credentials in one operation.

Microsoft confirmed the behavior is **"by design"** and does not plan a fix. No CVE has been assigned. While the threat requires prior elevation to admin/SYSTEM, the design significantly amplifies the payoff of any endpoint compromise, especially on shared infrastructure such as RDS and terminal servers where a single admin breach can yield credentials from many users simultaneously.

!!! note "No CVE — Vendor Design Decision"
    Microsoft classifies this as consistent with the expected security model: if an attacker has local admin rights, secrets on that endpoint are considered accessible via multiple means. Researchers argue the design unnecessarily broadens exposure vs. on-demand decryption alternatives.

## Technical Specifications

| Attribute | Details |
|---|---|
| **Affected Software** | Microsoft Edge (all Chromium-based builds; confirmed as of early May 2026) |
| **Trigger** | Browser startup — full vault decrypted into process memory immediately |
| **Storage at Rest** | AES-encrypted via DPAPI (passwords protected on disk) |
| **Storage in Memory** | Cleartext; remains resident while browser process is running |
| **Required Access Level** | Local Administrator or SYSTEM privileges on the target machine |
| **Exploitation Method** | Memory dump of `msedge.exe` via `ReadProcessMemory`, debugger APIs, or automated scanner |
| **CVE** | None — vendor classifies as by-design behavior |
| **Highest Risk Environment** | Shared RDS/terminal servers, jump boxes, VDI pools |
| **Researcher** | Lars Rønning (@L1v1ng0ffTh3L4N) |

## Affected Products

- **Microsoft Edge** — all current Chromium-based builds as of May 2026
- **Windows endpoints** running Edge with the built-in password manager enabled
- **Higher risk**: Windows Server environments running RDS, Citrix, terminal services, or shared VDI where multiple users have active or disconnected Edge sessions

## Attack Scenario

1. **Initial compromise** — Attacker gains local admin or SYSTEM privileges on a target Windows machine via a separate exploit (e.g., LPE, RCE), malware, credential theft, or misconfigured RDP
2. **Target identification** — On a shared server, the attacker enumerates running processes and identifies `msedge.exe` instances for each logged-on user, including those with disconnected but still-active sessions
3. **Memory dump** — Using an admin tool, custom script, or the researcher's proof-of-concept, the attacker reads Edge's process memory via `ReadProcessMemory` or debugger APIs
4. **Cleartext extraction** — Edge's in-memory decrypted password vault is parsed, yielding usernames, URLs, and plaintext passwords for every site stored in the browser's password manager — even those the user has not visited in the current session
5. **Credential reuse and lateral movement** — Stolen credentials are used to access corporate web apps, email, VPN, SaaS tools, and internal resources; password reuse across SSO-less internal services amplifies reach
6. **Scaled impact on shared systems** — On RDS/terminal servers, a single admin compromise can harvest credentials from many users simultaneously, turning one endpoint breach into a wide-scope credential dump

## Impact

=== "Enterprise Risk"

    - Any endpoint compromise reaching admin/SYSTEM on an Edge-running machine can convert into a full credential dump across all services where users have stored passwords
    - On shared systems (RDS/terminal servers, jump boxes, VDI), one admin breach can capture credentials for every logged-on and disconnected user running Edge
    - Particularly dangerous where corporate, privileged, or SaaS credentials are stored in Edge's built-in password manager

=== "Scope and Severity"

    - Affects all current Edge builds; no version-specific patch exists and none is planned
    - Risk is elevated where: users store corporate or admin credentials in Edge; endpoints are multi-user (Citrix/RDS/terminal servers); MFA is not enforced on target services
    - No active exploitation campaign has been reported; risk is amplified by a prior compromise, not exploitable standalone

=== "Vendor Stance"

    - Microsoft classifies the behavior as by-design and within the accepted threat model (admin access = local secret access)
    - No CVE will be issued; no security fix is planned
    - Security researchers argue alternatives such as on-demand decryption or tighter OS-level secure store integration would materially reduce the blast radius without sacrificing usability

## Mitigations

### For Enterprises

- **Govern Edge password manager use via Group Policy** — for high-risk environments (RDS, jump hosts, admin workstations), disable saving passwords in Edge using the `PasswordManagerEnabled` policy or equivalent Edge group policy settings; enforce this centrally via Intune or GPO
- **Prefer enterprise password managers or SSO** — use a dedicated credential vault (e.g., CyberArk, 1Password Business, Bitwarden Enterprise) or SSO (Entra ID, AD FS) so raw passwords are never resident in browser process memory; enforce MFA on all SSO flows
- **Apply least privilege rigorously** — remove local admin rights from standard user accounts to raise the bar for the attacker access level required to exploit this; enforce just-in-time admin where elevation is unavoidable
- **Harden shared server environments** — segregate user roles on RDS/terminal servers; avoid mixing privileged admins with regular users on the same host; disable Edge's password manager entirely on shared infrastructure
- **Deploy EDR with memory-dump detection** — use endpoint detection and response tooling to alert on or block memory-read operations targeting browser processes (`ReadProcessMemory` on `msedge.exe` / `chrome.exe`)
- **Patch LPE vulnerabilities promptly** — this issue requires admin/SYSTEM access; reducing the likelihood of privilege escalation is the most direct mitigating control

### For Users

- Avoid storing high-value, admin, or corporate passwords in browser-based password managers on shared or untrusted machines
- Enable MFA on all services so stolen passwords alone are insufficient for access
- On personal machines, consider a dedicated password manager that performs on-demand decryption rather than loading all credentials at startup

## Resources

!!! info "Open-Source Reporting"
    - [Microsoft Edge Passwords Enterprise Risk — Dark Reading](https://www.darkreading.com/cyber-risk/microsoft-edge-passwords-enterprise-risk)
    - [Microsoft Edge Stores All Saved Passwords in Cleartext Process Memory at Launch — Cryptika](https://www.cryptika.com/microsoft-edge-stores-all-saved-passwords-in-cleartext-process-memory-at-launch/)
    - [Microsoft Edge Plaintext Password Security Risk — SQ Magazine](https://sqmagazine.co.uk/microsoft-edge-plaintext-password-security-risk/)

---

*Last Updated: May 6, 2026*