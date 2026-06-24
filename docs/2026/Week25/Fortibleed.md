# FortiBleed Attackers Turn Firewalls Into Credential Stealers as Heists Persist
![alt text](images/Fortibleed.png)

**No Single CVE (Credential Harvesting Campaign)**{.cve-chip}  
**Credential Harvesting / Initial Access Operation**{.cve-chip}  
**Fortinet FortiGate / Edge Firewall Compromise**{.cve-chip}

## Overview
FortiBleed is a large-scale credential-harvesting campaign in which threat actors compromise Fortinet FortiGate firewalls and repurpose them into credential sniffers and VPN credential collectors. The operation is run by a Russian‑speaking initial‑access broker (IAB) and has targeted more than 430,000 FortiGate firewalls, harvesting an estimated 110 million credentials across many protocols. Valid admin and VPN credentials are extracted and then reused to access internal networks, VPN concentrators, and various externally facing services across multiple sectors.

## Technical Specifications

| **Attribute**        | **Details** |
|----------------------|-------------|
| **CVE ID**           | No single CVE; campaign abuses multiple vectors and legacy behaviors |
| **Vulnerability Type** | Credential harvesting, brute force, credential stuffing, and post-compromise credential sniffing |
| **CVSS Score**       | Not applicable as a single CVE; operational impact is effectively critical at ecosystem scale |
| **Attack Vector**    | Network (internet-exposed admin and VPN portals, edge devices) |
| **Authentication**   | Abuse of weak/reused credentials; once compromised, valid admin/VPN logins are used |
| **Complexity**       | Medium: operationally sophisticated infrastructure but uses common brute-force and sniffing techniques |
| **User Interaction** | Not directly user-driven; relies on misconfiguration, weak credentials, and lack of MFA |
| **Affected Versions**| FortiGate firewalls running FortiOS with internet-exposed admin/SSL‑VPN portals and legacy hash behavior; impact spans devices worldwide |

## Affected Products
- Fortinet FortiGate firewalls with internet-exposed admin and SSL‑VPN interfaces
- Approximately 73,000–87,000 FortiGate devices with harvested admin and SSL‑VPN credentials
- Organizations worldwide (194 countries), including:
  - Government and public sector
  - Telecommunications providers
  - Financial services
  - Healthcare providers
  - Manufacturing and other critical-infrastructure sectors
- Additional targeted platforms in the wider campaign:
  - Synology NAS
  - Sophos firewalls
  - RDWeb portals
  - Citrix SSL‑VPNs
  - MS‑SQL servers

## Attack Scenario

1. **Mass reconnaissance**  
   Threat actors use Masscan, Shodan, and custom tooling (FortiProbe‑fast, GeoSplit) to enumerate internet‑facing FortiGate firewalls and other targets, grouping them by country and service type.

2. **Credential attacks on exposed portals**  
   Brute‑force and credential‑stuffing campaigns are launched against FortiGate admin web UIs and SSL‑VPN portals, as well as other internet‑facing assets such as RDWeb, Citrix, MSSQL, Synology, and Sophos. Stolen credentials from prior breaches are reused to find accounts where passwords are the same.

3. **Compromise of FortiGate firewalls**  
   When authentication succeeds, attackers gain administrative GUI/SSH access to FortiGate devices. On compromised devices they deploy the Golang-based FortigateSniffer and related scripts, configuring them to run persistently in the background.

4. **Passive credential capture on the firewall**  
   FortigateSniffer uses the FortiOS diagnostic command `diagnose sniffer packet` to passively monitor traffic for around 24 protocols (RADIUS, TACACS+, Kerberos, NTLM/SMB, LDAP, RPC, RDP/WinRM, SMTP/IMAP/POP3, FTP/Telnet, MS‑SQL, MySQL, PostgreSQL, and more). Captured data includes cleartext usernames/passwords and authentication hashes, which are exfiltrated to attacker infrastructure.

5. **Cracking, validation, and reuse**  
   Collected hashes and tokens are fed into a 45‑GPU cracking cluster orchestrated via Hashtopolis and a Telegram bot (HASHBOT). Once cracked, credentials are validated and reused against Active Directory/LDAP, RDWeb, Citrix SSL‑VPN, VPN concentrators, MSSQL, and other externally accessible services. Using these valid credentials, attackers access internal networks, databases, and file shares, exfiltrate data, and may maintain persistence via credentials and session cookies.

## Impact Assessment

=== "Integrity"

    - Attackers can log into FortiGate firewalls as legitimate administrators and modify configurations, ACLs, and VPN policies.
    - Backdoor accounts and rogue admin profiles can be created to maintain long-term unauthorized access.
    - Internal directory and database integrity is at risk when AD and SQL credentials are reused for unauthorized configuration changes and privilege escalation.

=== "Confidentiality"

    - Harvested credentials cover tens of thousands of FortiGate devices and more than 21,000 corporate domains, exposing user and admin identities at scale.
    - Access to VPNs, AD, databases, and file shares enables the theft of sensitive corporate and personal data across government, financial, healthcare, and critical-infrastructure organizations.
    - Exfiltrated credential sets (e.g., RADIUS, NTLM, Kerberos, MySQL tokens) can be reused or resold, amplifying the long-term confidentiality impact.

=== "Availability"

    - Compromised firewalls can be used as stepping stones for disruptive operations, including ransomware deployment and destructive changes to network edge policies.
    - Configuration tampering on FortiGate devices can result in accidental or intentional outages for VPN and edge connectivity.
    - Widespread credential compromise increases the risk of multi-tenant or multi-service outages where shared infrastructure is involved.

## Mitigation Strategies

### Immediate Actions
- Use official FortiBleed lookup tools (e.g., SOCRadar and Hudson Rock checkers) to determine if your domains, URLs, or devices appear in the dataset.
- Immediately terminate all active FortiGate admin and SSL‑VPN sessions and force re-authentication.
- Rotate all FortiGate admin and SSL‑VPN credentials, including local accounts and any AD/LDAP accounts used for VPN authentication.
- Enforce MFA for all remote-access users and administrative accounts wherever supported.

### Short-term Measures
- Patch FortiOS to the latest supported release and apply all Fortinet security advisories and hardening guidance.
- Disable or restrict internet exposure of management and VPN portals; where exposure is unavoidable, protect them behind VPN, IP allowlists, or bastion hosts.
- Disable legacy or unused authentication protocols and ensure strong, unique passwords for all accounts, especially those used for VPN and administrative access.
- Assess and remediate historic compromises by reviewing whether earlier Fortinet vulnerabilities were fully fixed and credentials rotated.

### Monitoring & Detection
- Review FortiGate logs for:
  - Logins from unexpected IP addresses or geolocations
  - New or modified admin accounts and role changes
  - Unusual configuration changes, scheduled tasks, or CLI activity
- Hunt internally for indicators of post-FortiGate compromise:
  - Unexpected AD logins, new accounts, or privilege escalations
  - MSSQL/MySQL access from unusual hosts or service accounts
  - Large or anomalous data transfers from file servers and databases
- Monitor for the presence or execution of FortigateSniffer or suspicious diagnostic/sniffer commands on FortiGate devices.

## Resources and References

!!! info "Open-Source Reporting"
    - [Dark Reading – FortiBleed attackers turn firewalls into credential stealers](https://www.darkreading.com/cyberattacks-data-breaches/fortibleed-attackers-firewalls-credentials-stealers)
    - [The Hacker News – FortiBleed targeted FortiGate firewalls](https://thehackernews.com/2026/06/fortibleed-targeted-fortigate-firewalls.html)
    - [SOCRadar – FortiBleed: Fortinet firewalls compromised](https://socradar.io/blog/fortibleed-fortinet-firewalls-compromised/)
    - [CybelAngel – FortiBleed: 6 things to know](https://cybelangel.com/blog/fortibleed-6-things-to-know/)

---

*Last Updated: June 24, 2026*