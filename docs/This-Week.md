---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![IBM API Connect Vulnerability](2026/Week1/images/api_connect.png)

    **IBM API Connect Critical Authentication Bypass**

    **CVE-2025-13915**{.cve-chip} 
    **CVSS 9.8**{.cve-chip} 
    **Authentication Bypass**{.cve-chip} 
    **API Gateway**{.cve-chip}

    Critical authentication bypass vulnerability in IBM API Connect discovered during internal testing. CVE-2025-13915 allows unauthenticated attackers with network access to bypass authentication mechanisms and gain unauthorized access to applications and APIs protected by the platform. 

    Affects versions 10.0.8.0-10.0.8.5 and 10.0.11.0.
    No privileges or user interaction required for exploitation.

    [:octicons-arrow-right-24: View Full Details](2026/Week1/api_connect.md)

-   ![Transparent Tribe APT36 Campaign](2026/Week1/images/transparent_tribe.png)

    **Transparent Tribe RAT Campaign Targeting Indian Government and Academia**

    **APT36**{.cve-chip} 
    **Transparent Tribe**{.cve-chip} 
    **RAT**{.cve-chip} 
    **Spear-Phishing**{.cve-chip} 
    **Fileless Malware**{.cve-chip}

    Pakistan-attributed APT36 launches sophisticated cyber-espionage campaign against Indian government and academic institutions. 
    
    Spear-phishing emails deliver weaponized Windows LNK files disguised as PDFs. LNK triggers mshta.exe to execute HTA script that loads RAT (iinneldc.dll) entirely in memory without disk writes, evading traditional AV. 
    
    Adaptive persistence varies by detected antivirus (Kaspersky, Quick Heal, Avast/AVG/Avira). RAT provides remote control, file manipulation, screenshot/clipboard capture, keylogging, data exfiltration via encrypted HTTP C2. Targets classified government documents and sensitive research.

    [:octicons-arrow-right-24: View Full Details](2026/Week1/transparent_tribe.md)

</div>
