# Amazon: AI-Assisted Hacker Breached 600 Fortinet Firewalls in 5 Weeks
![alt text](images/fortinet.png)

**AI-Assisted Attack**{.cve-chip}  **Credential Abuse**{.cve-chip}  **FortiGate Firewalls**{.cve-chip}  **Financially Motivated**{.cve-chip}

## Overview
A Russian-speaking, financially motivated threat actor used multiple commercial generative AI services to help breach over 600 FortiGate firewalls in 55 countries between January 11 and February 18, 2026. Amazon's CISO reported that the actor had limited technical skills but compensated by using AI tools for reconnaissance, scripting, attack planning, and tooling development, effectively running an "AI-powered assembly line for cybercrime." Crucially, no Fortinet zero-day or product vulnerability was exploited—the intrusions relied on exposed management interfaces, weak or guessable passwords, and lack of multi-factor authentication on FortiGate admin access. This case demonstrates how AI drastically lowers the skill barrier for cyber attacks.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Incident Type** | AI-assisted credential abuse campaign |
| **Threat Actor** | Russian-speaking, financially motivated, low-skill |
| **Target** | FortiGate firewall management interfaces |
| **Geographic Scope** | 55+ countries worldwide |
| **Devices Compromised** | 600+ FortiGate firewalls |
| **Attack Duration** | January 11 - February 18, 2026 (5 weeks) |
| **Attack Vector** | Exposed management interfaces, weak credentials, no MFA |
| **Exploitation Method** | Brute force, password spraying (no CVE exploitation) |
| **AI Tools Used** | Multiple commercial generative AI services |

## Affected Products
- FortiGate firewalls with internet-exposed management interfaces (HTTPS/SSH)
- Systems lacking multi-factor authentication on admin access
- Devices with weak, default, or guessable administrative credentials
- Organizations across 55+ countries
- Status: Campaign concluded but underlying configuration weaknesses remain widespread

## Technical Details

### Target Profile
- Internet-exposed FortiGate firewall management interfaces (HTTPS/SSH)
- At least 55 countries affected worldwide
- Organizations with inadequate access controls on perimeter devices

### Attack Vector Analysis
**No Product Vulnerability Exploited:**

- No Fortinet zero-day or CVE exploited in this campaign
- Attack relied entirely on configuration and credential weaknesses
- Management interface exposure and authentication gaps enabled access

**Credential Compromise Methods:**

- Enumeration of FortiGate devices with open management ports
- Brute-force attacks against admin credentials
- Password spraying with common or weak passwords
- Exploitation of devices lacking multi-factor authentication

### AI-Assisted Attack Workflow

**Primary AI Service (Attack Orchestration):**

- Generated reconnaissance scripts for identifying exposed FortiGate devices
- Created exploitation code snippets (Python, Bash, shell scripts)
- Developed attack plans and operational workflows
- Automated brute-force and password-spraying tooling
- Generated custom wordlists for credential attacks

**Secondary AI Service (Tactical Copilot):**

- Assisted with post-compromise pivoting inside networks
- Helped craft commands for lateral movement
- Analyzed stolen configurations to identify targets
- Suggested privilege escalation and persistence techniques
- Provided real-time guidance for low-skill operator

### Post-Compromise Activities

**Configuration Exfiltration:**

- Full device configuration files extracted from compromised FortiGate devices
- Stolen data included:
    - Local and administrative account credentials
    - VPN settings and connection configurations
    - Network topology and routing information
    - Clear-text or weakly protected passwords
    - Internal IP addressing and subnets

**AI-Assisted Analysis:**

- Stolen configurations analyzed using AI tools
- AI identified additional reachable assets and pivot opportunities
- Generated commands and scripts for lateral movement
- Parsed complex configs to extract actionable intelligence

**Attack Infrastructure:**

- Attacker-controlled servers hosted:
    - AI-generated attack plans and operational documents
    - Victim configuration files and credentials
    - Custom tool source code and exploitation scripts
    - Analysis reports and target prioritization lists

![alt text](images/fortinet1.png)

## Attack Scenario
1. **AI-Assisted Reconnaissance**: 
    - Threat actor uses AI-generated scanning tools to identify IPs with FortiGate admin interfaces exposed to internet
    - AI helps automate and scale reconnaissance across global IP ranges
    - Identifies targets without MFA or with common configuration patterns

2. **Credential Attack Preparation**:
    - AI generates customized wordlists for password attacks
    - Creates automated brute-force and password-spraying scripts
    - Develops evasion techniques to avoid detection and rate limiting

3. **Initial Access via Weak Credentials**:
    - Applies password spraying and brute forcing against targets without MFA
    - AI tools help optimize attack speed and credential combinations
    - Successful login via web or SSH admin interface grants full admin rights

4. **Configuration Theft & Exfiltration**:
    - Pulls entire device configuration from compromised firewall
    - Exfiltrates configs to attacker-controlled infrastructure
    - Maintains access for future operations

5. **AI-Powered Configuration Analysis**:
    - Feeds stolen configurations into AI tooling for automated analysis
    - AI extracts user accounts, VPN configs, routing, and internal systems
    - Identifies high-value targets and pivot opportunities
    - Generates actionable intelligence from complex configuration data

6. **Lateral Movement Planning**:
    - AI proposes specific pivot steps and commands
    - Suggests which IPs/subnets to probe based on config analysis
    - Recommends methods to leverage VPN or management tunnels
    - Enables low-skill operator to behave like advanced intruder

7. **Mass-Scale Repetition**:
    - Same AI-assisted pattern applied to hundreds of devices
    - 5-week campaign demonstrates AI's ability to massively scale opportunistic attacks
    - No zero-days required—configuration weaknesses sufficient for mass compromise

## Impact Assessment

=== "Direct Infrastructure Compromise"
    * Compromise of 600+ perimeter security devices across 55 countries
    * Exposure of administrative credentials potentially reused in other systems
    * Detailed insight into network topology, VPN connections, and internal addressing
    * Complete visibility into firewall rules, policies, and security controls
    * Loss of trust in perimeter security infrastructure

=== "Intelligence & Future Attack Enablement"
    * Stolen configurations provide roadmap for targeted future attacks
    * VPN credentials enable direct internal network access
    * Network topology data facilitates lateral movement planning
    * Strong position for follow-on intrusions into internal networks
    * Access broker monetization opportunities for credential resale

=== "Strategic & Industry Impact"
    * AI drastically lowers skill barrier for sophisticated attacks
    * Modestly skilled individuals can now mount campaigns requiring organized teams
    * Demonstrates AI as "force multiplier" for cybercrime
    * Potential for data theft, ransomware partnerships, or persistent access sales
    * Shifts defensive requirements—traditional perimeter hardening insufficient against AI-augmented threats

## Mitigation Strategies

### Eliminate Management Interface Exposure
- **Remove Public Exposure**: Do NOT expose FortiGate management interfaces (HTTPS/SSH) directly to internet
- **Dedicated Management Networks**: Restrict admin access to isolated management VLANs
- **VPN/Jump Host Access**: Require secure VPN or bastion host for any remote administration
- **Network Segmentation**: Separate management plane from production traffic
- **Firewall Rules**: Implement strict source IP allowlisting for management access

### Enforce Strong Authentication
- **Multi-Factor Authentication**: Require MFA for ALL remote and administrative access without exception
- **Strong Password Policy**: Enforce long, complex, unique passwords for all admin accounts
- **Password Rotation**: Implement regular credential rotation schedules
- **Remove Default Accounts**: Eliminate or rename default administrative accounts
- **Account Inventory**: Maintain current inventory of all administrative users

### Fortinet-Specific Hardening
- **Apply Hardening Guidance**: Implement current Fortinet security best practices
- **Security Advisories**: Review and apply all relevant Fortinet security advisories
- **Firmware Updates**: Maintain current firmware versions with latest security patches
- **Disable Unused Services**: Turn off unnecessary protocols and services
- **API Access Controls**: Restrict and monitor API access for automation

## Resources and References

!!! info "Incident Reports"
    - [Amazon: AI-assisted hacker breached 600 Fortinet firewalls in 5 weeks](https://www.bleepingcomputer.com/news/security/amazon-ai-assisted-hacker-breached-600-fortigate-firewalls-in-5-weeks/)
    - [Hackers Used AI to Breach 600 Firewalls in Weeks - Bloomberg](https://www.bloomberg.com/news/articles/2026-02-20/hackers-used-ai-to-breach-600-firewalls-in-weeks-amazon-says)
    - [AI-Assisted Threat Actor Compromises 600+ FortiGate Devices in 55 Countries](https://thehackernews.com/2026/02/ai-assisted-threat-actor-compromises.html)
    - [LinkedIn: Countermeasures Group - AI-Augmented Threat Actor](https://www.linkedin.com/posts/countermeasures-group_ai-augmented-threat-actor-accesses-fortigate-activity-7430975201741348864-FIOd/)

---

*Last Updated: February 22, 2026* 