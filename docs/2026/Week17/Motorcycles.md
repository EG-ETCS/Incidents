# Electric Motorcycles and Scooters Bluetooth & Keyless Entry Vulnerabilities
![alt text](images/Motorcycles.png)

**IoT Security**{.cve-chip} **Bluetooth Vulnerability**{.cve-chip} **Keyless Entry Flaw**{.cve-chip} **Vehicle Security**{.cve-chip}

## Overview

Security researchers identified critical vulnerabilities in electric motorcycles and scooters from multiple manufacturers that allow nearby attackers to gain unauthorized access to vehicle systems. The flaws — a Bluetooth authentication bypass in Zero Motorcycles and a weak key fob authentication issue in Yadea scooters — could enable manipulation of vehicle behavior, unauthorized unlocking, and remote starting, posing both cybersecurity and physical safety risks to riders.

## Technical Specifications

| Attribute | Details |
|---|---|
| **Affected Vendors** | Zero Motorcycles (Bluetooth flaw); Yadea (key fob flaw) |
| **Vulnerability 1** | Bluetooth pairing without authentication (Zero Motorcycles) |
| **Vulnerability 2** | Insecure key fob communication — replay and spoofing attack (Yadea scooters) |
| **Attack Range** | Bluetooth range (proximity); RF signal range (key fob interception) |
| **Impact** | Unauthorized access, firmware manipulation, vehicle theft, safety risk |
| **CVEs** | Not publicly assigned at time of reporting |

## Affected Products

- **Zero Motorcycles** — models with Bluetooth connectivity and over-the-air pairing capability
- **Yadea electric scooters** — models using the affected key fob communication protocol

## Attack Scenarios

### Scenario 1 — Bluetooth Exploitation (Zero Motorcycles)

1. Attacker positions themselves within Bluetooth range of the target vehicle
2. Waits for the motorcycle to enter pairing mode (e.g., during owner setup or initiated by a trigger)
3. Connects to the vehicle without authentication due to the missing pairing verification
4. Uploads malicious firmware or sends direct control commands to vehicle systems
5. Gains unauthorized control over vehicle functions, potentially including throttle or braking behavior

### Scenario 2 — Key Fob Replay Attack (Yadea Scooters)

1. Attacker positions near the target scooter with RF signal capture equipment
2. Intercepts and records the key fob communication signal when the owner unlocks/locks the scooter
3. Replays or forges the recorded signal at a later time
4. Vehicle unlocks and starts without the legitimate key fob present

## Impact

=== "Safety Impact"

    - Manipulation of critical vehicle functions (throttle, braking) via malicious firmware could pose direct rider safety risks
    - Remote unlocking and starting enables vehicle theft without physical key access
    - Attacks may be undetectable by the rider until exploitation has occurred

=== "Broader Impact"

    - Loss of user trust in Bluetooth-connected and keyless smart vehicle technologies
    - Reputational risk for manufacturers if vulnerabilities are exploited at scale
    - Signals broader need for security standards in the growing electric micromobility sector

## Mitigations

### For Owners

- Apply firmware updates from Zero Motorcycles and Yadea as soon as they are available
- Avoid initiating Bluetooth pairing in public or unsecured areas where attackers could be within range
- Disable Bluetooth pairing mode on the vehicle when not actively pairing a new device
- Use additional physical security measures (e.g., disc locks, chain locks, alarm systems) as a compensating control

### For Manufacturers

- Implement strong mutual authentication for Bluetooth pairing (e.g., passkey or out-of-band confirmation)
- Use rolling codes or challenge-response protocols for key fob communication to prevent replay attacks
- Apply end-to-end encryption to all wireless vehicle communications
- Establish coordinated vulnerability disclosure programs and rapid firmware update delivery processes

## Resources

!!! info "Open-Source Reporting"
    - [Electric Motorcycles and Scooters Face Hacking Risks to Security and Rider Safety — SecurityWeek](https://www.securityweek.com/electric-motorcycles-and-scooters-face-hacking-risks-to-security-and-rider-safety/)
    - [Electric Motorcycles and Scooters Face Hacking Risks to Security and Rider Safety — OffSeq Threat Radar](https://radar.offseq.com/threat/electric-motorcycles-and-scooters-face-hacking-ris-b197840f)
    - [Electric Motorcycles and Scooters Face Hacking Risks to Security and Rider Safety — SOC Defenders](https://www.socdefenders.ai/item/d751856e-4897-437c-8682-dfd506326649)

---

*Last Updated: April 29, 2026*