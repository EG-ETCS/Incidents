# WhatsApp-Based Malware Campaign by Water Saci

**Banking Trojan**{.cve-chip}  
**WhatsApp Worm**{.cve-chip}  
**Brazil-Targeted**{.cve-chip}

## Overview

The campaign uses a sophisticated, multi-stage infection chain: attackers send malicious PDF or HTA attachments via WhatsApp appearing to come from trusted contacts. If opened, these trigger download of further payloads (an MSI installer + a Python script) that install a banking trojan and then propagate automatically to the victim's contacts via WhatsApp Web.

This **worm-like** propagation mechanism allows the malware to spread rapidly through WhatsApp contact lists, creating a large-scale compromise of Windows PCs belonging to WhatsApp-using Brazilians.

## Technical Specifications

| **Attribute**           | **Details**                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| **Threat Actor**        | Water Saci                                                                  |
| **Target Region**       | Brazil (Portuguese-language systems)                                        |
| **Target Platform**     | Windows PCs with WhatsApp Desktop/Web                                       |
| **Delivery Method**     | WhatsApp messages with malicious PDF or HTA attachments                     |
| **Malware Type**        | Banking Trojan with worm capabilities                                       |
| **Propagation**         | Automated via WhatsApp Web (Python script with Selenium)                    |
| **Target Sectors**      | Banking, cryptocurrency, payment platforms                                  |

![](images/watersaci1.png)

## Technical Details

### Initial Payload
- **PDF**: Lure to "update Adobe Reader"
- **HTA**: Runs VBScript

### Infection Chain
1. VBScript triggers **PowerShell** to fetch next-stage payloads:
      - An **MSI installer** (with AutoIt script)
      - A **Python script** for propagation

### AutoIt Installer Behavior
- Verifies one instance (checks for marker file `executed.dat`)
- Optionally contacts attacker-controlled server
- **Checks OS language is Portuguese (Brazil)** before proceeding
- Scans for banking-app related folders

### Trojan Capabilities

#### Monitoring & Targeting
- Monitors active windows/browser tabs
- Looking for banking or crypto-related sites (hard-coded lists including major Brazilian banks and crypto/payment platforms)
- On match, decrypts and injects payload via:
      - **Process hollowing** into `svchost.exe`
      - Direct injection, depending on presence of loader file (TDA) or DMP

#### Core Functions
- Send system info
- **Keylogging**
- **Screen capture**
- Mouse/keyboard simulation
- File operations
- Create **fake banking overlays** to harvest credentials
- Forcibly terminate browsers to force victims to reopen under attacker-controlled conditions

### Persistence & Stealth
- **Anti-virtualization checks**
- WMI queries for host data
- **Registry modifications** for persistence
- Fallback C2 via **IMAP**
- Checks for security software and avoids execution if environment not suitable

### Propagation Mechanism
- **Python-based script** uses browser automation (**Selenium / WhatsApp Web**)
- Sends malicious attachments/links to **all contacts**
- Making infection **worm-like and scalable**

![](images/watersaci2.png)

## Attack Scenario

1. **Initial Contact**: User receives a message on WhatsApp from a contact (likely already compromised), containing a malicious PDF or HTA.

2. **User Interaction**: User opens the attachment (perhaps thinking it's a legitimate document/update).

3. **Execution Chain**: 
      - HTA executes VBScript 
      - Launches PowerShell 
      - Downloads MSI installer + Python propagation script

4. **Installation**: AutoIt installs the banking trojan, performs checks:
      - Language verification
      - Prior infection check
      - Environment validation
      - If passing, drops & loads the trojan (via process injection or direct memory)

5. **Trojan Activation**: 
      - Trojan stays persistent
      - Monitors for banking app/browser use

6. **Worm Propagation**: Simultaneously the Python worm script:
      - Hijacks WhatsApp Web sessions (if logged in)
      - Sends malicious messages/files to **all contacts**
      - Spreading to new victims

7. **Chain Reaction**: Once new victims open the file, the chain repeats.

## Impact Assessment

=== "Scale of Compromise"
    * Potential **large-scale compromise** of Windows PCs belonging to WhatsApp-using Brazilians
    * **Worm-like propagation** — one infection can lead to many more via victims' contact lists
    * Enabling a **fast, broad spread**

=== "Financial Theft"
    * Theft of banking credentials
    * Crypto wallet credentials/payment credentials
    * Risk to banking sector trust
    * Increase in fraudulent transactions
    * Account takeovers
    * Money theft

=== "Remote Control"
    * Remote-control of infected machines
    * Attackers can:
         - Capture keystrokes
         - Capture screen
         - Exfiltrate files
         - Manipulate browser behavior
         - Execute transactions

=== "Detection Challenges"
    * Difficulty of detection and removal due to:
         - Stealth techniques
         - Anti-analysis mechanisms
         - In-memory loading
         - Persistence mechanisms

## Mitigations

### 👤 User Awareness
- **Avoid opening unsolicited attachments** even if they appear to come from trusted contacts on WhatsApp (especially PDFs, ZIPs, HTA)
- Do not use WhatsApp Web / desktop when logged in on a PC that might be risky
- At least avoid downloading/executing attachments from it

### 🛡️ Endpoint Security
- Use **robust endpoint security** with behavioral detection (not just signature-based)
- Able to catch:
      - Script-based execution
      - Process injection
      - Unusual child processes (`mshta.exe` → PowerShell/Python → unusual executables)

### 🔄 System Hardening
- **Keep OS and applications up-to-date**
- **Disable or restrict execution** of HTA/AutoIt/PowerShell from untrusted sources
- Restrict use of scripting or automation tools if not needed

### 📚 Security Awareness
- **Educate users** about phishing/social engineering risks, especially via messaging platforms
- Promote security awareness before opening files

### 🏦 For Financial Institutions
- Monitor unusual login patterns
- Prompt for **two-factor authentication**
- Detect anomalous transactions
- Encourage customers to use trusted devices

### 📱 For WhatsApp/Meta
- Restrict or block the propagation of executable or archive attachments via WhatsApp Web
- Warn users about risks

## Resources & References

!!! info "Research & Analysis"
    * [Brazil Hit by Banking Trojan Spread via WhatsApp Worm and RelayNFC NFC Relay Fraud](https://thehackernews.com/2025/12/brazil-hit-by-banking-trojan-spread-via.html)
    * [More sophisticated Water Saci attack methods uncovered | SC Media](https://www.scworld.com/brief/more-sophisticated-water-saci-attack-methods-uncovered)
    * [Water Saci Threat Actor Evolves Tactics to Deploy Banking Trojan via WhatsApp | Blog - Comfidentia](https://blog.comfidentia.cl/en/2025/12/03/water-saci-evolves-tactics-banking-trojan-whatsapp/)

!!! warning "Target Region"
    This campaign specifically targets **Portuguese-language Windows systems in Brazil**. The malware checks for Portuguese (Brazil) OS language before proceeding with infection.