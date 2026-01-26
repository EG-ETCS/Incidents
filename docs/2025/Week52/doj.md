# U.S. DOJ Charges 54 in ATM Jackpotting Scheme Using Ploutus Malware

![DOJ ATM Jackpotting](images/doj1.png)

**ATM Malware**{.cve-chip} 
**Physical Attack**{.cve-chip} 
**Organized Crime**{.cve-chip} 
**$40.73M Stolen**{.cve-chip}

## Overview

The **U.S. Department of Justice** indicted **54 individuals** for participating in a **multi-million-dollar conspiracy** involving **ATM jackpotting** using **Ploutus malware** to force ATMs to dispense cash without valid transactions. The operation involved **physical intrusion** into ATM cabinets, installation of specialized malware to command cash dispensers, and subsequent **money laundering**. The stolen funds, totaling approximately **$40.73 million** across over **1,500 incidents** since 2021, were allegedly laundered and partially funneled to support the **Venezuelan criminal organization Tren de Aragua**, designated as a **foreign terrorist organization**. This case represents a significant intersection of **cybercrime, organized crime, and terrorism financing**.

---

## Case Specifications

| **Attribute**              | **Details**                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| **Case Authority**         | U.S. Department of Justice                                                 |
| **Defendants Charged**     | 54 Individuals                                                             |
| **Criminal Organization**  | Tren de Aragua (TdA) — Venezuelan Foreign Terrorist Organization           |
| **Malware Used**           | Ploutus — ATM Jackpotting Malware                                          |
| **Attack Type**            | Physical Intrusion + Malware Installation                                  |
| **Total Financial Loss**   | Approximately $40.73 Million (as of August 2025)                           |
| **Incident Count**         | Over 1,500 ATM Jackpotting Incidents (since 2021)                          |
| **Target Systems**         | Bank and Credit Union ATMs (primarily older Windows-based systems)         |
| **Attack Complexity**      | Moderate (requires physical access + technical malware deployment)         |
| **Affected Regions**       | Nationwide (United States)                                                 |

---

## Technical Details

### Ploutus Malware

**Ploutus** is a specialized **ATM jackpotting malware** designed to interface directly with the **cash dispenser module** of automated teller machines:

- **Malware Functionality**: Issues unauthorized commands to the ATM's cash dispenser, forcing it to eject bills without legitimate withdrawal transactions
- **Anti-Forensics**: Attempts to delete traces of its presence after execution to hinder detection and forensic analysis
- **Target Systems**: Primarily affects ATMs running outdated operating systems (e.g., **Windows XP**) with insufficient endpoint protection
- **Modular Design**: Can be deployed via pre-infected hard drives or removable media (USB drives)

### Attack Methodology

The ATM jackpotting operation combined **physical intrusion** with **malware deployment**:

1. **Physical Access**: Attackers used various methods to breach ATM cabinets:
    - **Lock Picking**: Manipulation of standard locks on ATM service panels
    - **Key Duplication**: Use of stolen or duplicated maintenance keys
    - **Drilling**: Physical destruction of locking mechanisms
    - **Forced Entry**: Breaking or prying open access panels

2. **Malware Deployment**: Two primary installation methods:
    - **Hard Drive Replacement**: Swapping the ATM's hard drive with a pre-infected drive containing Ploutus
    - **Removable Media**: Booting from USB drive and loading malware into ATM system memory

3. **Cash Dispensing**: Once installed, Ploutus bypasses transaction validation and directly commands the cash dispenser to eject currency

4. **Clean-Up**: Malware attempts self-deletion and log erasure to complicate investigation

---

## Attack Scenario

### Step-by-Step Operation

1. **Reconnaissance and Target Selection**  
    - Criminals conducted surveillance on ATMs to assess physical security measures, alarm systems, camera coverage, and foot traffic patterns. 
    - Targeted standalone ATMs in low-visibility locations with minimal surveillance.

2. **Physical Intrusion**  
    - Attackers gained physical access to ATM internal components by opening service panels using stolen keys, lock picking tools, or drilling through locking mechanisms. 
    - Some incidents involved cutting power or disabling alarm systems.

3. **Malware Deployment**  
   Ploutus malware installed via one of two methods: 
    - Removing existing hard drive and replacing with pre-infected drive containing malware. 
    - Inserting USB drive and booting from external media to load malware into system memory.

4. **Cash Extraction ("Jackpotting")**  
    - Attackers triggered Ploutus to send unauthorized commands to cash dispenser. 
    - ATM ejected bills without recording legitimate transactions. 
    - Criminals collected cash, often filling bags with tens of thousands of dollars per machine.

5. **Evidence Removal and Laundering**  
    - Malware attempted to delete itself and clear system logs. 
    - Stolen cash was split among conspirators, laundered through shell companies and cash-intensive businesses, with portions allegedly directed to **Tren de Aragua** leadership in Venezuela.

---

## Impact Assessment

=== "Financial Impact" 
    * Approximately **$40.73 million** stolen across **1,500+ incidents** since 2021. 
    * Individual ATM losses ranged from $10,000 to $100,000 per jackpotting event. 
    * Banks and credit unions faced direct cash losses plus costs for ATM repair/replacement, security upgrades, and operational downtime. 
    * Insurance claims and litigation added secondary financial burden.

=== "Operational Impact"
    * Each compromised ATM required immediate decommissioning for forensic analysis and hardware replacement. 
    * Financial institutions experienced service interruptions at affected locations. 
    * Reputation damage from repeated incidents led to customer concerns about ATM security. 
    * Increased security measures (guards, surveillance) imposed ongoing operational costs.

---

## Mitigation Strategies

### Physical Security Hardening

- **Tamper-Proof Locks**: Upgrade ATM service panels with high-security locks resistant to picking and drilling. Install anti-drill plates and reinforced hinges.
- **Alarm Systems**: Deploy motion sensors, door contact switches, and accelerometers that trigger immediate alerts when ATM cabinet opened. Integrate with 24/7 monitoring centers.
- **Video Surveillance**: Install high-resolution cameras with night vision covering ATM front and rear. Ensure footage retention for minimum 90 days. Position cameras to capture faces and license plates.
- **Secure Locations**: Prioritize ATM placement in well-lit, high-traffic areas with natural surveillance. Avoid isolated or poorly monitored locations vulnerable to extended intrusion attempts.

### Software and Firmware Hardening

- **Operating System Updates**: **Phase out Windows XP and other end-of-life OS**. Migrate to modern, supported operating systems with active security patching (Windows 10 IoT Enterprise, Linux-based ATM software).
- **Endpoint Protection**: Deploy specialized ATM security software with runtime monitoring, application whitelisting, and behavioral analysis to detect malicious processes.
- **Secure Boot**: Enable secure boot mechanisms requiring cryptographically signed operating systems and drivers. Prevents loading of unauthorized software from external media.
- **Full Disk Encryption**: Encrypt ATM hard drives to prevent malware installation via drive replacement. Use hardware-based encryption (TPM) where available.
- **USB Port Controls**: Disable or physically block USB ports on ATMs. If USB required for maintenance, implement strict authentication and logging of all USB device connections.

### Monitoring and Detection

- **Transaction Anomaly Detection**: Implement real-time monitoring for abnormal cash dispenser activity (e.g., rapid sequential dispensing without corresponding transactions, off-hours dispensing patterns).
- **System Integrity Monitoring**: Deploy file integrity monitoring (FIM) to detect unauthorized changes to ATM software, configuration files, and system binaries.
- **Network Monitoring**: Monitor ATM network traffic for anomalous patterns, unauthorized connections, or command-and-control communications.
- **Incident Logging**: Maintain comprehensive logs of ATM access events, maintenance activities, system reboots, and hardware changes. Centralize logs for correlation and analysis.

### Operational Controls

- **Maintenance Procedures**: Implement strict two-person rule for ATM maintenance. Require sign-off, video recording, and supervisor notification for all hardware access.
- **Key Management**: Secure ATM service keys in monitored access control systems. Track key usage and investigate any unexplained access.
- **Staff Training**: Train bank personnel, security guards, and ATM technicians to recognize signs of tampering (scratches around locks, residue from drilling, displaced panels).
- **Vendor Vetting**: Ensure third-party ATM service providers undergo background checks and adhere to security protocols. Audit vendor access logs regularly.

---

## Resources

!!! info "Media Coverage"
    - [U.S. DOJ Charges 54 in ATM Jackpotting Scheme Using Ploutus Malware](https://thehackernews.com/2025/12/us-doj-charges-54-in-atm-jackpotting.html)
    - [US DoJ Charges 54 Linked to ATM Jackpotting Scheme Using Ploutus Malware, Tied to Tren de Aragua - IT Security News](https://www.itsecuritynews.info/us-doj-charges-54-linked-to-atm-jackpotting-scheme-using-ploutus-malware-tied-to-tren-de-aragua/)
    - [ATM Jackpotting ring busted: 54 indicted by DoJ](https://www.webpronews.com/doj-charges-54-in-tren-de-araguas-40m-atm-jackpotting-scheme/)
    - [U.S. DOJ Press Release — 54 Charged in ATM Jackpotting Scheme](https://securityaffairs.com/185908/cyber-crime/atm-jackpotting-ring-busted-54-indicted-by-doj.html)
    - [54 Arrested in $Multi-Million ATM Jackpotting Scheme Linked to Tren de Aragua](https://www.redhotcyber.com/en/post/54-arrested-in-multi-million-atm-jackpotting-scheme-linked-to-tren-de-aragua/)
    - ['Jackpotting': 50 Tren de Aragua gang members imported under Dems indicted in nationwide ATM scheme * WorldNetDaily * by Jim Hoft, the Gateway Pundits](https://www.wnd.com/2025/12/jackpotting-50-tren-de-aragua-gang-members-imported/)
    - [Tren de Aragua Leaders Indicted in Major ATM Jackpotting Scheme - TechNadu](https://www.technadu.com/tren-de-aragua-members-indicted-in-us-multi-million-dollar-atm-jackpotting-scheme/616199/)
    - [DOJ Charges 54 Alleged Tren De Aragua Members](https://dallasexpress.com/national/doj-charges-54-alleged-tren-de-aragua-members-in-nationwide-atm-hacking-scheme/)
    - [54 Charged in Nationwide ATM Jackpotting Scheme Linked to Venezuelan Terror Group](https://townhall.com/tipsheet/scott-mcclallen/2025/12/18/54-charged-in-nationwide-atm-jackpotting-scheme-linked-to-venezuelan-terror-group-n2668165)
