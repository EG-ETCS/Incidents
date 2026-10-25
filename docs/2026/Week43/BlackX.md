# BlackX UEFI Bootkit Targeting Central Asian Diplomatic Organizations
![alt text](images/BlackX.png)

**BlackX**{.cve-chip} **UEFI Bootkit**{.cve-chip} **Secure Boot Bypass**{.cve-chip} **APT41 (Medium Confidence)**{.cve-chip} **Diplomatic Targeting**{.cve-chip}

## Overview

Kaspersky discovered a cyber-espionage campaign using a UEFI bootkit named BlackX against diplomatic organizations in Central Asia, particularly Tajikistan, Uzbekistan, and Turkmenistan. The activity was identified in early 2026 and publicly described in October 2026.

BlackX bypasses Secure Boot protections, loads a malicious Windows kernel driver, and deploys espionage payloads. Kaspersky attributes the operation to APT41 with medium confidence. This is a researcher assessment, not a newly announced government attribution.

A key finding is that affected victims were running fully patched Windows releases but had not activated the additional Secure Boot revocations required to block vulnerable boot components. Installing Windows updates alone had therefore not completed the relevant protection.

## Technical Details

### Bootkit and Secure Boot bypass

BlackX is a UEFI bootkit that targets the system boot process. Its Secure Boot bypass implementation is described as remarkably similar to BlackLotus, which previously exploited the Baton Drop vulnerability (CVE-2022-21894).

The reported implementation allows attackers to enroll custom Machine Owner Keys (MOKs) and load arbitrary EFI files. BlackX differs from BlackLotus in its kernel driver and subsequent payloads.

The reporting does not disclose the initial-access method or exact privileges used to install BlackX. It should not be described as an unauthenticated remote exploit or as proof that an attacker can compromise an otherwise inaccessible device simply because Secure Boot revocations are missing.

### Relationship to BlackLotus

Kaspersky assesses that BlackX was developed either through reverse-engineering BlackLotus or by obtaining its source code. Researchers found code shared between BlackX and BlackLotus samples that was absent from the incomplete BlackLotus source-code leak published in July 2023.

This supports a technical relationship between the bootkits but does not, by itself, establish identical operators.

### Malicious kernel driver

BlackX loads a malicious Windows kernel driver signed with a now-revoked certificate issued to Wenjiang District Mingyu Network Technology Service Studio.

Reported driver capabilities include:

- Disabling security-related processes and Windows Registry callbacks.
- Tampering with Event Tracing for Windows (ETW) providers to obstruct monitoring.
- Performing selected tampering actions when Kaspersky or Avast products are detected.
- Interfering with attempts to open bootkit files and launching Windows Calculator instead.

Kaspersky states the mechanism intended to interfere with its products is ineffective against its solutions. The attempted interference should therefore not be reported as confirmed successful disablement of Kaspersky protection.

### Espionage payloads

The driver also supports deployment of two reported payloads:

- A remote-access Trojan using Google Drive, OneDrive, or Yandex.Disk for command-and-control (C2), with file transfer and .NET payload execution support.
- OxiDLLRunner, an obfuscated DLL sideloaded by googleupdate.exe that decrypts v8_context_snapshot.bin to launch shellcode and a Rust payload, then retrieves DLL plugins from archivetj[.]com.

These services and filenames are investigation leads, not standalone proof of compromise. Google Drive, OneDrive, Yandex.Disk, and Google-related executable names can also appear in legitimate activity.

### Patch and revocation gap

According to Kaspersky, victims had installed Windows updates but had not manually activated additional Secure Boot revocations. The report identifies revocation of trust in the Windows Production PCA 2011 certificate as an important control for preventing vulnerable boot components from loading.

Microsoft documents the relevant Windows Boot Manager revocation process in KB5025885, associated with CVE-2023-24932. Administrators should distinguish the Baton Drop identifier cited in incident reporting from related Secure Boot mitigation guidance and follow Microsoft's current platform-specific procedure.

The reporting also warns certificate expiration alone does not prevent vulnerable components from loading; required revocation and blocklist changes must be applied.

### Attribution and exploitation status

- Attribution: APT41 with medium confidence, according to Kaspersky.
- Exploitation: Confirmed use in an espionage campaign identified in early 2026.
- Current activity: Reporting does not establish whether the campaign remained operational at publication time.
- Undisclosed details: Victim identities, total device count, initial-access method, intrusion duration, and volume of stolen data.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Campaign Name** | BlackX |
| **Malware Class** | UEFI bootkit with kernel-level follow-on components |
| **Primary Technique** | Secure Boot bypass and boot-chain manipulation |
| **Noted Related CVE** | CVE-2022-21894 (Baton Drop context / BlackLotus similarity) |
| **Mitigation Guidance Reference** | KB5025885 (CVE-2023-24932 Secure Boot revocation workflow) |
| **Kernel Component** | Malicious signed driver with anti-monitoring and tampering behavior |
| **Follow-on Payloads** | Cloud-service-enabled RAT and OxiDLLRunner plugin chain |
| **Attribution Statement** | APT41 with medium confidence (researcher assessment) |

## Affected Products

- Windows endpoints with UEFI Secure Boot configurations susceptible due to incomplete revocation state.
- Environments where vulnerable boot components remain trusted despite regular OS patching.
- Diplomatic-sector organizations were the confirmed target vertical in this reported campaign.

## Attack Scenario

1. Attacker obtains sufficient access to deploy the bootkit (initial access path not disclosed).
2. BlackX abuses Secure Boot bypass mechanics and incomplete revocation protection.
3. Attacker-controlled EFI components load during boot.
4. A malicious kernel driver executes within Windows and attempts to degrade monitoring/security visibility.
5. Espionage payloads are deployed, enabling remote tasking, plugin retrieval, and file transfer.
6. Boot-level persistence and monitoring interference complicate detection and forensic investigation.

## Impact Assessment

### Confirmed findings

- Diplomatic organizations in Tajikistan, Uzbekistan, and Turkmenistan were targeted.
- BlackX bypassed Secure Boot on systems that were patched for Windows updates but lacked required additional revocation activation.
- A malicious driver and espionage payload chain supported remote execution and file transfer capabilities.

### Potential impact

Boot-chain compromise plus kernel-level tampering can significantly increase risk to confidentiality of diplomatic communications and documents, while reducing trust in endpoint telemetry and system integrity.

The reporting does not quantify stolen data or claim destructive wiping, ransomware encryption, broad operational outages, or physical consequences.

### Sector and technology scope

Confirmed targeting is in diplomacy. Technologies involved (Windows, UEFI, Secure Boot, and cloud-storage services) are widely used across government and enterprise environments, but exposure depends on boot configuration state, applicable updates/revocations, and attacker access capability.

## Mitigation Strategies

1. Validate full Secure Boot mitigation state using Microsoft KB5025885, including required boot-manager updates, Secure Boot database changes, and revocations.
2. Test boot and recovery compatibility before broad revocation rollout, including updated installation and recovery media.
3. Hunt for reported execution-chain indicators involving googleupdate.exe, sideloaded DLL behavior, v8_context_snapshot.bin, and archivetj[.]com correlations.
4. Examine signs of security-monitoring interference, including abnormal process termination, unexpected driver loads, Registry callback issues, and ETW disruption.
5. Preserve evidence and isolate suspected hosts, collecting EFI partition artifacts, memory evidence, logs, and boot-configuration data before disruptive remediation.
6. Recover and validate the boot chain, not just Windows userland artifacts; rotate potentially exposed credentials and revoke sessions from trusted devices after scoping.

## Resources and References

!!! info "Public Reporting"
    - [BleepingComputer - BlackX UEFI bootkit exploits Baton Drop flaw to bypass Secure Boot (October 24, 2026)](https://www.bleepingcomputer.com/news/security/blackx-uefi-bootkit-exploits-baton-drop-flaw-to-bypass-secure-boot/)
    - [Kaspersky - Beneath the operating system: Kaspersky discovers BlackX bootkit targeting diplomatic organizations in Central Asia (October 21, 2026)](https://www.kaspersky.com/about/press-releases/beneath-the-operating-system-kaspersky-discovers-blackx-bootkit-targeting-diplomatic-organizations-in-central-asia)
    - [Microsoft Support - Manage Windows Boot Manager revocations for Secure Boot changes associated with CVE-2023-24932 (KB5025885)](https://support.microsoft.com/en-gb/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d)

---

*Last Updated: October 25, 2026*
