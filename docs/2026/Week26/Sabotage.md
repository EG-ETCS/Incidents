# Iran, Russia, China Target Water Systems for Sabotage
![alt text](images/Sabotage.png)

**No Single CVE**{.cve-chip}  
**ICS/OT Targeting**{.cve-chip}  
**Water & Wastewater Infrastructure**{.cve-chip}  
**Hybrid Warfare / Sabotage**{.cve-chip}

## Overview
Nation-state actors linked to Iran, Russia, and China are systematically targeting water and wastewater systems worldwide, predominantly by exploiting basic security weaknesses rather than sophisticated ICS zero-day vulnerabilities.Their campaigns focus on exposed PLCs and HMIs, weak or default passwords, poorly secured remote-access tools, and vulnerable edge devices in order to create psychological pressure, generate propaganda, conduct limited physical sabotage, and pre-position themselves for future conflict.

Research highlighted by DomainTools and reporting from Poland, Norway, Israel, the United States, and elsewhere show that relatively low-tech intrusions into inadequately segmented and monitored environments have already produced concrete operational impacts, underscoring a broader hybrid-warfare pattern.

## Technical Specifications

| **Attribute**         | **Details** |
|-----------------------|-------------|
| **CVE ID**            | No single CVE; campaigns exploit systemic weaknesses |
| **Vulnerability Type**| Weak authentication, exposed ICS/OT, poor segmentation, insecure remote access |
| **CVSS Score**        | Not applicable (campaign-level threat) |
| **Attack Vector**     | Network (internet-exposed OT/IT, remote access, vendor portals) |
| **Authentication**    | Often weak/default credentials or reused passwords |
| **Complexity**        | Low to Medium (primarily misconfigurations and basic vulns) |
| **User Interaction**  | Not typically required; attacks target exposed services |
| **Affected Versions** | Water and wastewater utilities using exposed PLCs/HMIs, flat IT/OT networks, legacy systems and remote-access tooling |

## Common Initial Access Paths
- Exposed PLCs and HMIs on the internet with no authentication or weak protection.
- Weak, default, or reused passwords on OT and IT systems.
- Poorly secured remote-access tools (VPN, RDP, vendor remote support).
- Legacy, unsupported systems with limited monitoring and flat IT/OT network architectures.

## Country-Specific Activity

### Iran
- **Actors:** CyberAv3ngers and other IRGC-linked groups focusing on US, Israeli, and broader regional water systems.
- **TTPs:** Scan for exposed PLCs and control systems, log in opportunistically, and use access for defacement, propaganda, and fear rather than consistently sophisticated sabotage.
- **Example:** A thwarted 2020 attempt against Israeli water systems that could have disrupted supply during a heat wave, widely cited as a watershed example of OT targeting by Iranian-linked actors.
- **Risk:** High for small, internet-exposed utilities with poor controls; moderate where OT environments are well segmented and monitored.

### Russia
- **Actors:** Sandworm and fronts such as “Cyber Army of Russia Reborn,” linked to GRU units and known for disruptive ICS operations.
- **TTPs:** More willing than Iran to manipulate water control systems directly, including pumps, tanks, and floodgates.
- **Examples:**
  - **Muleshoe, Texas (Jan 2024):** Attackers accessed a remote industrial interface and caused a municipal water tank overflow for 30–45 minutes; the incident was claimed by Cyber Army of Russia Reborn and linked by Mandiant to Sandworm.
  - **Norway (2025 floodgate case):** Norwegian counter-intelligence officials attributed a floodgate manipulation releasing roughly 400 liters per second for several hours to Russia, illustrating direct physical impact.
  - **Poland (2025 breaches):** Polish authorities reported compromises at five water treatment plants via default passwords and internet-exposed control systems; Russian and Belarusian APTs were suspected of probing and altering ICS settings.
- **Risk:** High for European and NATO-adjacent states; moderate to high for exposed US municipal systems.

### China
- **Main actor:** Volt Typhoon, known for long-term pre-positioning in US critical infrastructure.
- **Activity:** CISA/NSA/FBI joint advisories in early 2024 documented Volt Typhoon compromises in US water and wastewater systems alongside other sectors, with behavior focused on stealthy access and persistence.
- **Goals:** Durable access, reconnaissance, and strategic pre-positioning for future conflict rather than immediate sabotage; activity is consistent with preparing options to disrupt civilian infrastructure in time of crisis.
- **Risk:** Assessed as severe for long-term activity and latent disruption potential, with lower short-term likelihood of overt attacks.

## Attack Scenario

### Reconnaissance and Exposure Mapping
- Nation-state actors scan for internet-exposed HMIs/PLCs, VPNs, RDP gateways, billing portals, vendor remote-access systems, and other OT-adjacent services belonging to water utilities.
- They compile target lists across municipalities, regions, and countries, focusing on weakly defended utilities and critical chokepoints.

### Initial Compromise
- Use factory-default or weak passwords, credential reuse, or simple web/application vulnerabilities to log into OT or SCADA-adjacent systems, often without ICS-specific malware.
- In some cases, compromise IT systems such as billing, GIS, vendor access, remote admin portals, identity systems, or backup servers and pivot toward OT.

### Access to Water Operations
- Once inside, they may:
  - Manipulate pumps, tanks, valves, or floodgates to cause overflows, pressure changes, or localized flooding.
  - Quietly map the environment, plant backdoors, and maintain a long-term foothold in critical systems (especially in China-linked campaigns).
- Some documented incidents stopped short of altering chemical dosing or filtration, but those capabilities were within reach given the level of access.

### Effects and Messaging
- **Iran-linked operations:** Publicize screenshots or minor disruptions for propaganda and fear, amplifying psychological impact disproportionate to technical complexity.
- **Russia-linked operations:** Conduct small-scale sabotage (tank overflows, floodgate opening) to test resilience, create local damage, and generate public concern.
- **China-linked operations:** Largely silent and focused on future leverage; communications emphasize stealth and persistence over visible disruption.

## Impact Assessment

### Operational and Safety Risk
- Potential to interrupt water supply or pressure, cause overflows or flooding, damage infrastructure, and in severe cases manipulate treatment processes.
- Even limited operational disruptions at small utilities can produce outsized real-world impact when they affect drinking water or wastewater handling.

### Psychological and Political Impact
- Water is directly tied to public health and trust; claimed access or brief disruptions can trigger fear, political pressure, and media attention.
- These campaigns are used to test government response, erode confidence in infrastructure security, and support broader influence operations.

### Strategic / Geopolitical
- Water systems are treated as strategic pressure points in hybrid warfare, allowing Iran and Russia to exert pressure and probe resilience, and China to pre-position capabilities for potential future conflict.
- Activity against water utilities mirrors patterns seen in energy, transportation, and other critical sectors, reinforcing the need for sector-agnostic ICS security improvements.

### Systemic Lessons
- Attacks largely succeed because of exposed devices, weak credentials, poor network segmentation, and limited monitoring rather than bespoke ICS malware.
- The same structural weaknesses exist in many sectors, meaning lessons from water utilities apply broadly across OT environments.

## Mitigation Strategies

### Lock Down Remote and Internet Exposure
- Remove direct internet exposure of PLCs and HMIs; place them behind firewalls, VPNs, or one-way gateways.
- Restrict vendor and remote access with strong authentication, IP allow-lists, and time-bound access windows.

### Strengthen Authentication Basics
- Eliminate default accounts and shared credentials; enforce strong, unique passwords and MFA for all remote and administrative access.
- Implement rigorous password policies and credential management for both IT and OT systems.

### IT/OT Segmentation and Monitoring
- Implement strong segmentation between IT and OT networks; avoid flat architectures that allow easy pivoting.
- Monitor for anomalous logins, new accounts, unusual commands on HMIs/PLCs, and suspicious activity on SCADA-adjacent servers.

### Address “Shadow OT/IT”
- Inventory and secure billing systems, customer portals, GIS repositories, vendor-access servers, identity systems, and backup platforms that connect to or sit adjacent to OT.
- Apply consistent access control, logging, and hardening across these supporting systems.

### Defense-in-Depth, Not Just Basics
- Begin with general controls: patching, password hygiene, centralized logging, and robust backups.
- Layer OT-specific controls: engineered safety interlocks, one-way data diodes where appropriate, protocol-aware monitoring, and ICS-aware intrusion detection.
- Regularly test incident response plans for OT scenarios, including water supply disruptions and treatment anomalies.

## Resources and References

!!! info "Official Documentation"
    - [NJCCIC – China-Linked Cyber Operations Targeting U.S. Critical Infrastructure](https://www.cyber.nj.gov/threat-landscape/nation-state-threat-analysis-reports/china-linked-cyber-operations-targeting-us-critical-infrastructure)
    - [Dark Reading – Iran, Russia, China Target Water Systems for Sabotage](https://www.darkreading.com/ics-ot-security/iran-russia-china-target-water-systems-sabotage)
    - [CNBC – America’s Drinking Water Under Attack: China, Russia, and Iran](https://www.cnbc.com/2024/06/26/americas-drinking-water-under-attack-china-russia-and-iran.html)
    - [SocDefenders – Iran, Russia, China Target Water Systems for Sabotage](https://www.socdefenders.ai/item/aa83ccd1-5808-4623-b764-5ac05834487f)

---

*Last Updated: June 30, 2026*