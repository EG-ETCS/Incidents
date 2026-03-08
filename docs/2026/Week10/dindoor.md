# Iranian APT Hacked US Airport, Bank, Software Company
![alt text](images/dindoor.png)

**Iran-Linked APT**{.cve-chip}  **Dindoor Backdoor**{.cve-chip}  **Fakeset Malware**{.cve-chip}  **Critical Sector Targeting**{.cve-chip}

## Overview
Researchers reported a coordinated espionage campaign attributed to Iran-linked operators targeting organizations across aviation, banking, and software supply-chain sectors. The activity involved persistent access operations, deployment of custom backdoors, and attempts to exfiltrate sensitive data, including from an Israeli branch of a software supplier tied to defense industries.

The campaign indicates strategic intelligence collection objectives focused on long-term access to high-value environments.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Threat Context** | Iran-linked espionage campaign (MuddyWater/Seedworm-linked reporting context) |
| **Primary Malware** | Dindoor (newly reported backdoor), Fakeset (Python backdoor) |
| **Execution Environment** | Dindoor executed via Deno runtime (JavaScript/TypeScript) |
| **Code Signing Indicators** | Certificates observed with names including "Amy Cherne" and "Donald Gay" |
| **Targeted Sectors** | Airport/aviation, banking, NGO/non-profit, defense-adjacent software ecosystem |
| **Operational Goal** | Persistent access, reconnaissance, data exfiltration, strategic intelligence collection |
| **C2 Capability** | Remote command-and-control and task execution |
| **Campaign Style** | Multi-victim, cross-sector, long-term persistence-focused intrusion activity |

## Affected Products
- Enterprise Windows/Linux environments in targeted organizations
- U.S. airport network infrastructure (reported victim context)
- U.S. banking-sector systems (reported victim context)
- Israeli branch systems linked to defense-relevant software supply chain
- Status: Active threat model; organizations with similar exposure patterns may remain at risk

## Technical Details

### 1) Dindoor Backdoor
- Newly reported malware used for persistent remote access.
- Observed in:
    - U.S. bank
    - Canadian NGO
    - Israeli branch of targeted software company
- Operates through Deno runtime execution paths.
- Signed with a certificate reportedly issued for "Amy Cherne".

### 2) Fakeset Backdoor
- Python-based backdoor observed in:
    - U.S. airport network
    - Non-profit organization networks
- Provides command-and-control capability for remote tasking.
- Code-signing artifacts include names such as "Amy Cherne" and "Donald Gay" referenced in prior MuddyWater-linked reporting.

### 3) Operational Behavior
- Emphasis on stealthy persistence and longitudinal access.
- Lateral movement and internal reconnaissance to identify strategic systems.
- Data collection/exfiltration attempts against high-value business and supply-chain nodes.

## Attack Scenario
1. **Initial Compromise**:
    - Attackers obtain access through phishing or exposed/stolen credentials.

2. **Persistence Establishment**:
    - Dindoor and/or Fakeset implants are deployed on compromised hosts.

3. **Privilege Expansion**:
    - Adversary moves laterally and increases access across internal systems.

4. **Reconnaissance**:
    - Internal assets are mapped to locate sensitive operational and strategic data.

5. **Data Exfiltration Attempts**:
    - High-value information is targeted, including defense-adjacent supply-chain data.

6. **Long-Term Access**:
    - Stealth persistence maintained for continued intelligence collection.

## Impact Assessment

=== "Confidentiality"
    * Exposure of financial and operationally sensitive information
    * Potential compromise of defense supply-chain intelligence
    * Expanded espionage risk across interlinked enterprise environments

=== "Integrity"
    * Unauthorized persistent access to critical business systems
    * Potential tampering of internal tooling and trust relationships
    * Elevated risk from signed-malware trust abuse patterns

=== "Availability"
    * Operational disruption risk in airport and enterprise IT environments
    * Increased incident response burden due to multi-stage persistence
    * Potential follow-on campaigns leveraging established footholds

## Mitigation Strategies

### Certificate Abuse Detection
- Monitor for suspicious binaries signed with names such as:
    - `Amy Cherne`
    - `Donald Gay`
- Flag anomalous trust events tied to unexpected code-signing chains

### Network and Exfiltration Defense
- Segment critical infrastructure and sensitive business zones
- Monitor outbound traffic for exfiltration-like patterns and unusual beaconing
- Restrict unmanaged east-west movement paths

### Identity and Access Hardening
- Enforce MFA across privileged and remote access channels
- Implement privileged access monitoring and rapid credential rotation
- Reduce standing admin privileges and strengthen account governance

### Endpoint and Threat Hunting
- Deploy/maintain EDR with detection logic for Deno/Python backdoor behaviors
- Hunt for persistence artifacts (scheduled tasks, run keys, unusual startup paths)
- Investigate suspicious C2 communications and lateral movement indicators

## Resources and References

!!! info "Open-Source Reporting"
    - [Iranian APT Hacked US Airport, Bank, Software Company - SecurityWeek](https://www.securityweek.com/iranian-apt-hacks-us-airport-bank-software-company/)
    - [Iran Seedworm hackers inside US critical networks | Cybernews](https://cybernews.com/security/iran-seedworm-hackers-us-israeli-critical-network/)
    - [Symantec reports Iranian Seedworm hackers infiltrate US infrastructure and defense supply chain networks - Industrial Cyber](https://industrialcyber.co/ransomware/symantec-reports-iranian-seedworm-hackers-infiltrate-us-infrastructure-and-defense-supply-chain-networks/)
    - [Iranian APT group MuddyWater targets multiple US companies | SC Media](https://www.scworld.com/news/iranian-apt-group-muddywater-targets-multiple-us-companies)
    - [Iran-Linked MuddyWater Hackers Target U.S. Networks With New Dindoor Backdoor](https://thehackernews.com/2026/03/iran-linked-muddywater-hackers-target.html?m=1)

---

*Last Updated: March 8, 2026* 
