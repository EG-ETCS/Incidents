# Spitting Cash: ATM Jackpotting Attacks Surged in 2025
![alt text](images/jackpotting.png)

**ATM Jackpotting**{.cve-chip}  **Ploutus Malware**{.cve-chip}  **Physical Attack**{.cve-chip}  **Financial Crime**{.cve-chip}

## Overview
In 2025, ATM jackpotting attacks surged sharply in the United States, with the FBI recording over 700 jackpotting incidents in 2025 alone out of approximately 1,900 total since 2020, causing more than $20 million in losses in 2025 and roughly $40 million+ since 2021. These attacks use malware (notably Ploutus) and "black-box" techniques to force ATMs to dispense cash on demand by targeting the ATM's embedded Windows system and cash-dispenser interface, bypassing normal transaction flows without debiting customer accounts. Attackers combine physical access (using generic master keys to open ATM cabinets) with logical attacks (installing malware on Windows-based ATM systems) to gain complete control over cash dispensers.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Attack Type** | ATM Jackpotting (logical physical attack) |
| **Primary Malware** | Ploutus (Windows-based ATM malware) |
| **Attack Method** | Physical access + malware installation |
| **Target Systems** | Windows-based ATMs with XFS cash-dispenser APIs |
| **Access Method** | Generic master keys, lock-picking, physical tampering |
| **US Incidents (2020-2025)** | ~1,900 total, 700+ in 2025 alone |
| **Financial Losses (2025)** | >$20 million (US) |
| **Total Losses (2021-2025)** | ~$40 million+ (US) |
| **Notable Case** | DOJ indictment: 54 individuals, 117 attempts, $5.4M losses |

## Affected Products
- ATMs running Windows operating systems (particularly legacy versions)
- Cash dispensers using XFS (eXtensions for Financial Services) APIs
- ATMs with generic or widely-available master locks
- Off-site and lobby ATMs with weaker physical security
- Isolated ATMs in retail locations and gas stations
- Status: Ongoing active threat with increasing frequency

## Technical Details

### Jackpotting Definition
- **Logical attack** making ATM "spit out" cash ("jackpot")
- **No legitimate card transaction** or customer account debiting
- **Direct cash dispenser control** bypassing normal banking flows
- **Targets ATM terminal** itself, not bank back-ends or customer accounts

### Ploutus Malware Characteristics
- **Platform**: Designed for ATMs running Windows
- **Legacy**: Exists for over a decade, continuously evolved
- **Target API**: Interacts directly with XFS / cash-dispenser APIs
- **Bypass Mechanism**: Issues dispense commands outside normal transaction flows
- **Control Method**: Gives attackers near-total control over ATM cash dispensing
- **Speed**: Enables rapid cash-out in minutes before operator detection

### Initial Access & Infection Methods

**Physical Access Techniques**:

1. **Generic Master Keys**: Use widely-available online ATM master keys
2. **Lock-Picking**: Pick or bypass ATM cabinet locks
3. **Physical Tampering**: Force open ATM cabinets using tools

**Installation Options**:

**Option A - Hard Drive Modification**:

- Remove ATM's internal hard drive
- Connect HDD to attacker's laptop
- Install Ploutus malware on drive
- Reinsert modified drive into ATM

**Option B - External Device Boot**:

- Plug USB drive or external device into internal USB/SATA ports
- Boot from "black box" controller or pre-loaded hard drive
- Run Ploutus directly from external hardware
- Send dispense commands without modifying ATM's original drive

### Attack Behavior
- **Complete Control**: Near-total control over ATM cash-dispensing functions
- **Rapid Cash-Out**: Trigger cash dispensing in less than 10 minutes per machine
- **Detection Evasion**: No stolen card data or suspicious account activity appears
- **Fraud Detection Challenges**: Harder to detect as normal banking fraud indicators absent
- **Persistence**: Malware sometimes left on ATM for reuse in future attacks

### Scale & Attribution
- **FBI Statistics**: ~1,900 cases since 2020; 700+ in 2025
- **2025 Losses**: >$20 million in confirmed losses
- **DOJ Case (Dec 2025)**: 54 individuals indicted
    - Some linked to Venezuelan gang Tren de Aragua
    - At least 117 jackpotting attempts
    - $5.4M confirmed losses + $1.4M attempted using Ploutus
    - Targeted banks and credit unions

## Attack Scenario

1. **Reconnaissance**: Survey isolated ATMs with weak locks, poor surveillance, and slow police response.

2. **Physical Access**: Use generic master keys or lock-picking to open ATM cabinet and access internal PC.

3. **Malware Deployment**:
    - *Hard Drive Method*: Remove HDD, install Ploutus on attacker's laptop, reinsert.
    - *External Device Method*: Boot from USB or "black box" without modifying original drive.

4. **Cash Dispensing**: Execute Ploutus, send dispense commands directly to cash-dispenser hardware, extract cash in <10 minutes.

5. **Exit**: Collect cash, remove evidence or leave malware for reuse, exit before reconciliation.

6. **Detection**: Theft discovered only during cash reconciliation; no fraud alerts or account activity triggers investigation delay.

## Impact Assessment

=== "Financial Losses"
    * Over $20 million stolen in US in 2025 alone
    * Cumulative losses ~$40 million+ since 2021
    * Individual law enforcement cases show multimillion-dollar heists per crew
    * Losses across dozens to hundreds of ATMs per criminal group
    * Insurance claims and recovery costs for financial institutions
    * Replacement costs for compromised ATM hardware

=== "Operational & Security Impact"
    * Combination of physical and logical attack vectors
    * Exploitation of weaknesses in ATM locks, casing, and legacy Windows platforms
    * Increased insurance premiums and protective costs for banks
    * Complex incident response and forensic investigation requirements
    * Need for enhanced physical security and monitoring infrastructure
    * Operational disruption from ATM downtime during investigation

=== "Industry & Systemic Risk"
    * Many ATM fleets run old or poorly secured Windows builds
    * Weak XFS hardening makes systems attractive targets
    * Legacy systems with vendor support challenges
    * Attack methodology commoditized and repeatable
    * Low technical skill barrier once tools like Ploutus available
    * Tactical crews trained with repeatable playbooks
    * Threat expanding from organized crime to broader criminal networks

=== "Customer & Public Impact"
    * ATM availability reduced in affected areas
    * Potential for service disruption during investigations
    * Loss of cash access in underbanked communities
    * Public confidence in ATM security undermined
    * Increased fees or reduced ATM deployments in high-risk areas

## Mitigation Strategies

### Physical Security Hardening
- **Lock Replacement**: Replace generic master locks with unique, high-security locks
- **Key Management**: Strict tracking and access control for ATM keys
- **Casing Reinforcement**: Reinforce ATM casings against physical tampering
- **Tilt/Door Alarms**: Install sensors detecting cabinet opening or movement
- **Video Surveillance**: Improve camera coverage and recording quality around ATMs
- **Lighting**: Enhance lighting in ATM areas to deter tampering
- **Location Assessment**: Relocate or enhance security for isolated high-risk ATMs

### Hardware & Port Protection
- **Port Locking**: Lock or disable internal USB/SATA ports where feasible
- **Port Blocking Devices**: Install physical port blocking mechanisms
- **Tamper-Evident Seals**: Use seals around PC compartments and cash safes
- **Access Sensors**: Deploy sensors detecting unauthorized hardware connections
- **BIOS/Boot Protection**: Configure BIOS to prevent booting from external devices
- **Hardware Encryption**: Use encrypted connections between ATM components

### Software & Operating System Security
- **OS Upgrades**: Upgrade ATMs to supported, patched Windows versions
- **Patch Management**: Apply all vendor security patches promptly
- **XFS Hardening**: Implement vendor-recommended XFS API hardening
- **Application Whitelisting**: Allow only approved executables to run
- **Endpoint Protection**: Deploy antivirus and endpoint detection where vendor-supported
- **Ploutus Detection**: Monitor for known Ploutus artifacts (processes, files, registry keys)

### Long-term Strategic Defenses
- **Next-Generation ATMs**: Deploy ATMs with modern security architectures
- **Hardware Security Modules**: Use HSMs for cryptographic operations
- **Secure Boot**: Implement secure boot and trusted execution environments
- **Continuous Monitoring**: Invest in 24/7 ATM monitoring infrastructure
- **Industry Collaboration**: Participate in financial services information sharing (FS-ISAC)
- **Regulatory Advocacy**: Support standards and regulations for ATM security
- **Research & Development**: Invest in advanced ATM security technologies

## Resources and References

!!! info "Incident Reports"
    - [Spitting Cash: ATM Jackpotting Attacks Surged in 2025](https://www.darkreading.com/cyber-risk/atm-jackpotting-attacks-surged-2025)
    - [FBI: Over $20 million stolen in surge of ATM malware attacks in 2025](https://www.bleepingcomputer.com/news/security/fbi-over-20-million-stolen-in-surge-of-atm-malware-attacks-in-2025/)
    - [ATM Jackpotting Incidents Skyrocketed in 2025 With the Help of Malware](https://www.pcmag.com/news/atm-jackpotting-incidents-skyrocketed-in-2025-with-the-help-of-malware)
    - [FBI Reports 1,900 ATM Jackpotting Incidents Since 2020](https://thehackernews.com/2026/02/fbi-reports-1900-atm-jackpotting.html)

---

*Last Updated: February 24, 2026* 