# SonicWall SMA 1000 zero-day SSRF and command-injection vulnerabilities - CVE-2026-83548 and CVE-2026-83549
![alt text](images/SonicWall.png)

**Zero-Day Exploitation**{.cve-chip} **SonicWall SMA 1000**{.cve-chip} **CVE-2026-83548**{.cve-chip} **CVE-2026-83549**{.cve-chip} **Perimeter Appliance Risk**{.cve-chip}

## Overview

SonicWall released emergency updates for two actively exploited zero-day vulnerabilities affecting Secure Mobile Access (SMA) 1000 appliances: **CVE-2026-83548** and **CVE-2026-83549**. SonicWall indicated the flaws may be chained to move from unauthorized access conditions to command execution on vulnerable devices.

SonicWall confirmed active exploitation in at least one investigated case, but public reporting does not identify the responsible threat actor, victim organizations, malware family, or full forensic sequence. This is a confirmed zero-day exploitation event with limited public technical disclosure.

## Technical Details

### Affected Product

- SonicWall **Secure Mobile Access (SMA) 1000** VPN appliances.

### Vulnerabilities

- **CVE-2026-83548**: SSRF vulnerability in the Appliance WorkPlace interface.
- **CVE-2026-83549**: Command injection vulnerability in the Appliance Management Console (AMC) under the documented conditions.

### Potential Attack Chain (Publicly Reported)

- SonicWall reported active exploitation and warned the two vulnerabilities may be chained.
- A likely progression is SSRF-enabled access facilitation followed by AMC command injection.
- The exact transition path from SSRF behavior to the required AMC access state is not publicly disclosed and should be treated as unconfirmed.

### Affected Versions

- SMA 1000 **12.4.3-03453 (platform-hotfix) and earlier**.
- SMA 1000 **12.5.0-02835 (platform-hotfix) and earlier**.

### Fixed Versions

- **12.4.3-03526 (platform-hotfix)**.
- **12.5.0-02952 (platform-hotfix)**.

### Attribution and Malware Status

- **Threat actor**: Unknown (no public attribution by SonicWall).
- **Malware used in this case**: Not publicly disclosed.
- Prior SMA 1000 incidents involving CVE-2026-15409/CVE-2026-15410, UTA0533, and KNUCKLEBALL are distinct and should not be treated as confirmed linkage to this campaign.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Vendor** | SonicWall |
| **Product Family** | Secure Mobile Access (SMA) 1000 |
| **CVE-2026-83548 Type** | Server-Side Request Forgery (SSRF) |
| **CVE-2026-83549 Type** | Command Injection |
| **Exploitation Status** | Confirmed active exploitation by vendor investigation |
| **Potential Chaining** | Yes, reported as potentially chainable |
| **Public Attribution** | Not disclosed |
| **Public Malware Details** | Not disclosed |
| **Affected Builds** | 12.4.3-03453 and earlier; 12.5.0-02835 and earlier |
| **Patched Builds** | 12.4.3-03526; 12.5.0-02952 |
| **Criticality Note** | CVE-2026-83548 reported with CVSS 10.0 in public coverage |

## Affected Products

- SonicWall SMA 1000 appliances on vulnerable platform-hotfix versions.
- Organizations exposing SMA management or remote-access surfaces to the internet without strict access controls.
- Environments where compromised VPN gateways could enable access to broader internal infrastructure.

## Attack Scenario

1. Attacker identifies internet-reachable SonicWall SMA 1000 appliances running vulnerable versions.
2. Attacker exploits **CVE-2026-83548** in Appliance WorkPlace to trigger SSRF under pre-auth conditions.
3. SSRF condition is used to facilitate access to otherwise restricted functions or services.
4. Attacker exploits **CVE-2026-83549** in AMC to execute arbitrary operating-system commands with administrator-level impact under required conditions.
5. Post-compromise, attacker may alter appliance settings, harvest credentials, establish persistence, and pivot toward internal assets.

The exact intermediate steps in the exploitation chain have not been publicly disclosed by SonicWall.

## Impact Assessment

=== "Confirmed Impact"

    - SonicWall confirmed active zero-day exploitation involving CVE-2026-83548 and CVE-2026-83549
    - Successful chaining can lead to arbitrary command execution on affected SMA 1000 appliances

=== "Potential Impact"

    - Compromise of a remote-access gateway can expose VPN trust boundaries and sensitive authentication paths
    - Attackers may modify policies, create persistence, or pivot to internal systems
    - These effects are technically plausible for compromised VPN appliances but are not publicly confirmed as observed outcomes in this specific case

=== "Sector Relevance"

    - SMA 1000 devices are used across enterprise, government, critical infrastructure, healthcare, education, and managed-service environments for secure remote access
    - Public sources do not provide verified Egyptian victim attribution, but organizations operating affected versions should treat this as urgent globally

## Mitigation Strategies

### Apply SonicWall Hotfixes Immediately

- Upgrade affected SMA 1000 systems to **12.4.3-03526** or **12.5.0-02952** as applicable.
- Verify installed platform-hotfix versions after maintenance completion.

### Conduct Compromise Assessment

- Review SonicWall advisories and hunt for vendor-provided indicators of compromise (IOCs).
- Audit administrative logins, configuration changes, unusual WorkPlace/AMC access, new accounts, and anomalous outbound connections.

### Re-image if Indicators Are Found

- If compromise indicators exist, re-image or re-deploy affected appliances rather than relying only on patching.
- Rebuild from trusted vendor-approved images and restore only known-good configuration data.

### Rotate Credentials and MFA Material

- Reset user and administrator credentials where compromise is suspected.
- Reset TOTP/MFA seeds per vendor guidance when indicators are present.
- Rotate related VPN, directory, API, service-account, and privileged credentials as needed.

### Reduce Management-Surface Exposure

- Restrict WorkPlace and AMC administration access to trusted networks and allowed administrator source ranges.
- Avoid direct internet exposure of management interfaces when controlled access paths can be used.
- Enforce MFA and least privilege on all appliance administration accounts.

### Hunt for Follow-on Intrusion

- Treat confirmed SMA compromise as potential internal initial access.
- Investigate for lateral movement, unusual remote sessions, suspicious privileged account activity, and persistence mechanisms.

## Resources and References

!!! info "Public Reporting"
    - [Attackers Exploit Two SonicWall SMA 1000 Zero-Days to Breach VPN Appliances](https://thehackernews.com/2026/09/attackers-exploit-two-sonicwall-sma.html)

---

*Last Updated: September 03, 2026*