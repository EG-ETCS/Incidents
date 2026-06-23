# Usbliter8 Apple BootROM Exploit
![alt text](images/Apple.png)

**BootROM Exploit**{.cve-chip} **Unpatchable**{.cve-chip} **A12/A13 Chips**{.cve-chip} **Physical Access**{.cve-chip} **Chain-of-Trust Bypass**{.cve-chip}

## Overview

Security researchers disclosed a new exploit named "Usbliter8" that bypasses Apple boot defenses on devices using A12 and A13 chips. The exploit targets vulnerabilities in the BootROM and USB controller during early boot stages, enabling arbitrary code execution before iOS security protections fully initialize. Because BootROM is hardware-embedded and immutable after manufacturing, the vulnerability cannot be fully patched on affected devices. High-value targets such as journalists, government personnel, and executives face elevated risk.

## Technical Specifications

| Attribute | Details |
|---|---|
| **Exploit Name** | Usbliter8 |
| **Vulnerability Location** | Apple BootROM + USB controller firmware configuration |
| **Affected Chips** | Apple A12, Apple A13 |
| **Attack Vector** | Physical (USB-connected malicious device) |
| **Example Attack Hardware** | Raspberry Pi Pico 2 or similar USB device |
| **Exploitation Technique** | Crafted USB packets triggering memory corruption during boot sequence |
| **Patchability** | Not fully patchable — BootROM is hardware-embedded and immutable post-manufacturing |
| **Impact** | Arbitrary code execution before iOS security protections initialize, privilege escalation, chain-of-trust bypass |
| **CVE IDs** | Not yet assigned |

## Affected Products

- iPhone XS, XS Max, XR (A12 chip)
- iPhone 11, 11 Pro, 11 Pro Max (A13 chip)
- iPad Air 3, iPad mini 5, iPad 8 (A12 chip) , iPad 9 (A13 chip)
- Apple Watch Series 4, Apple Watch Series 5, first-generation Apple Watch SE 
- Any Apple device with an A12 or A13 SoC running affected BootROM firmware

## Attack Scenario

1. Attacker gains physical access to a target iPhone or compatible Apple device with an A12 or A13 chip.
2. The device is connected to a specially crafted malicious USB device (e.g., a Raspberry Pi Pico 2 loaded with the exploit payload).
3. During the device's boot sequence, the malicious USB payload delivers crafted packets that trigger the BootROM memory corruption vulnerability.
4. Boot protections are bypassed before iOS security measures fully initialize.
5. The attacker executes unauthorized code with elevated privileges at the lowest level of the device's software stack.
6. The attacker may perform forensic data extraction, advanced jailbreaking, or use the access to develop further attack chains.

## Impact

=== "Integrity"

    - Bypass of Apple's chain-of-trust boot protections, undermining the entire iOS security model
    - Arbitrary code execution at the BootROM level before iOS security controls load
    - Potential for developing persistent implants or future attack chains leveraging the low-level access

=== "Confidentiality"

    - Forensic data extraction from affected devices, including encrypted storage
    - Unauthorized access to protected system functions and sensitive user data
    - Advanced jailbreaking enabling access to data normally protected by iOS sandboxing and encryption

=== "Availability"

    - Increased risk for high-value targets: journalists, government personnel, executives, and activists
    - Device compromise enabling surveillance or monitoring by sophisticated threat actors
    - Affected devices (A12/A13) cannot be fully protected via software update — hardware replacement required for full mitigation

## Mitigations

### Immediate Actions

- Avoid connecting devices to untrusted USB accessories, charging cables, or public charging stations
- Use USB data blockers when charging in untrusted locations
- Enable **Lockdown Mode** on devices belonging to high-risk users (journalists, executives, government personnel)

### Short-term Measures

- Keep devices updated with the latest iOS releases to benefit from any available software-level mitigations
- Use strong alphanumeric passcodes to limit the value of physical access
- Restrict physical access to devices — maintain custody of devices at all times in high-risk environments

### Monitoring & Detection

- Monitor for indicators of device jailbreaking or unauthorized system modifications
- High-risk organizations should conduct periodic mobile device integrity checks
- Be alert to suspicious USB accessories or unfamiliar charging equipment

### Long-term Solutions

- Replace affected A12/A13 devices with newer hardware featuring updated BootROM protections where threat model warrants it
- Apple's future chip generations (A14 and later) are not reported as affected; hardware refresh mitigates the risk
- Adopt a mobile security policy that treats physical device custody as a critical security control

## Resources

!!! info "Open-Source Reporting"
    - [New Exploit Bypasses Apple's Boot Defenses, Affects Millions of iPhones | SecurityWeek](https://www.securityweek.com/new-exploit-bypasses-apples-boot-defenses-affects-millions-of-iphones/)
    - [New unpatchable exploit targets Apple devices with A12 and A13 chips | 9to5Mac](https://9to5mac.com/2026/06/18/new-unpatchable-exploit-targets-apple-devices-with-a12-and-a13-chips/)
    - [Unpatchable Exploit Found in Apple's A12 and A13 Chips | Privacy Guides](https://www.privacyguides.org/news/2026/06/19/unpatchable-exploit-found-apples-a12-and-a13-chips/)

---

*Last Updated: June 23, 2026*
