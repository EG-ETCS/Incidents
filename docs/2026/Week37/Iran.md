# Iranian hackers use CHOSEN BRICK Windows malware to spy on targets
![alt text](images/Iran.png)

**State-Linked Espionage**{.cve-chip} **CHOSEN BRICK**{.cve-chip} **Social Engineering**{.cve-chip} **Telegram C2**{.cve-chip} **Windows Surveillance Malware**{.cve-chip}

## Overview

Government agencies from the United States, United Kingdom, and the Netherlands, alongside the FBI, warned that Iranian state-linked operators are using Windows malware known as **CHOSEN BRICK** to conduct surveillance and espionage.

Reported targeting focuses on dissidents, activists, journalists, and other individuals viewed as threats to the Iranian regime, particularly in the United States, United Kingdom, and Netherlands. The campaign relies on social engineering through messaging platforms rather than exploitation of a software CVE.

## Technical Details

### Threat Actor and Targeting Context

- Joint government advisory attributes activity to Iranian state-linked actors.
- Assessment states Iran almost certainly uses cyber operations to support repression of dissidents and critics abroad.
- Public article text does not name a specific APT group identifier.

### Initial Access and Social Engineering

- Attackers contact targets via WhatsApp or Telegram.
- Messages impersonate trusted contacts or technical-support staff.
- Victims are persuaded to execute malicious files disguised as legitimate applications.
- Lures may include medical-themed or support-themed pretexts.
- Targets may be encouraged to install on personal devices to bypass enterprise security controls.

### Malware Installation and Persistence

- Fake application presents a convincing user interface while installing CHOSEN BRICK in the background.
- Persistence established through Windows Registry Run keys.
- Microsoft Defender exclusions may be added to reduce detection likelihood.

### CHOSEN BRICK Capabilities

- Collect system information.
- Enumerate running processes.
- Capture screenshots.
- Record microphone audio.
- Steal email content.
- Steal Telegram and WhatsApp browser-stored data.
- Download additional payloads into `C:\Windows\SysWOW64`.
- Delete files.
- Wipe the entire host system.

### C2, Exfiltration, and Evasion

- Infected hosts communicate with distinct Telegram bot infrastructure per victim context.
- Exfiltration may use Telegram and cloud-storage services.
- Newer variants may route traffic through SOCKS5 proxies.
- Advisory recommends investigating unexpected traffic related to Telegram APIs, Backblaze B2, VultrObjects, StorjShare, IPRoyal, and LightningProxies.

### Exploitation Status

- Confirmed active espionage campaign per joint government warning.
- No CVE is central to this campaign; compromise depends on successful social engineering and victim execution.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Malware Family** | CHOSEN BRICK |
| **Campaign Type** | Targeted surveillance and espionage |
| **Attribution Basis** | Joint U.S./U.K./Netherlands/FBI government advisory |
| **Primary Delivery Channel** | WhatsApp and Telegram social engineering |
| **Primary Target Profile** | Dissidents, activists, journalists, and related individuals |
| **Primary Geography (Reported)** | United States, United Kingdom, Netherlands |
| **Persistence Method** | Windows Registry Run keys |
| **Defense Evasion** | Microsoft Defender exclusions |
| **C2/Exfil Pathways** | Telegram bots, cloud-storage services, SOCKS5 proxy routing |
| **Destructive Capability** | File deletion and full host wipe |

## Affected Products

- Windows endpoints used by targeted individuals.
- Messaging-driven trust channels (WhatsApp/Telegram) leveraged for delivery.
- Accounts and data accessible from compromised hosts, including email and messaging/browser artifacts.

## Attack Scenario

1. Operator selects high-interest individual target.
2. Attacker initiates WhatsApp/Telegram contact while impersonating trusted contact or support role.
3. Victim receives and executes disguised malicious application.
4. CHOSEN BRICK is installed silently behind a decoy interface.
5. Malware establishes persistence and weakens endpoint defenses.
6. Host communicates with Telegram-based C2 and exfiltration channels.
7. Data theft and surveillance continue; in some cases stolen data may be published on pro-Iranian leak platforms for harassment pressure.

## Impact Assessment

=== "Confirmed Campaign Impact"

    - Persistent surveillance and data theft against selected Windows victims
    - Collection of communications-related data, screenshots, audio, and system details
    - Cross-border monitoring pressure on dissidents and civil-society targets

=== "Potential Victim Risk"

    - Account compromise and impersonation exposure
    - Harassment, doxxing, or reputational harm from data leakage
    - Additional downstream targeting enabled by stolen communications/context data

=== "Criticality"

    - **High** due to targeted surveillance depth, anti-detection behavior, and destructive wipe capability
    - Not currently classified as broad infrastructure-critical disruption in available public evidence

## Mitigation Strategies

### Block High-Risk Delivery Paths

- Do not install EXEs, archives, APKs, or "security fixes" received via messaging apps or unsolicited channels.
- Install software only from official vendor sources or approved enterprise portals.

### Verify Requests Out-of-Band

- Independently confirm support requests or software-install instructions through separate trusted channels.
- Treat requests to shift activity from managed work device to personal device as a high-risk indicator.

### Hunt Persistence and Evasion Artifacts

- Inspect Registry Run keys for unknown persistence entries.
- Review Microsoft Defender exclusions and remove unauthorized entries.
- Investigate suspicious payload presence in `C:\Windows\SysWOW64`.

### Monitor Network and Account Signals

- Investigate anomalous connectivity to Telegram APIs, Backblaze B2, VultrObjects, StorjShare, IPRoyal, and LightningProxies.
- Correlate suspicious network signals with process anomalies, microphone usage, and unusual browser/messaging data access.

### Contain and Recover Safely

- Isolate suspected devices from network connectivity while preserving forensic evidence.
- Avoid immediate wiping if legal/safety/forensic requirements apply.
- Reset passwords, revoke sessions, and rotate credentials for services accessed on affected endpoints.

### Protect High-Risk Users

- Enforce MFA, preferably phishing-resistant methods, on email/cloud/messaging-linked accounts.
- Use managed, regularly patched devices for sensitive communications.
- Provide targeted training and support for journalists, activists, diaspora communities, and other high-risk groups.

### Backup and Resilience

- Maintain offline or immutable backups of critical files.
- Test restoration procedures to reduce impact of file deletion or full-host wipe behavior.

## Resources and References

!!! info "Public Reporting"
    - [Iranian hackers use CHOSEN BRICK Windows malware to spy on targets](https://www.bleepingcomputer.com/news/security/iranian-hackers-use-chosen-brick-windows-malware-to-spy-on-targets/)

---

*Last Updated: September 17, 2026*