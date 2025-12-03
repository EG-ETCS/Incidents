---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![MuddyWater Campaign](Week49/images/muddy.png)
    :material-shield-alert:{ .lg .middle } **MuddyWater MuddyViper Backdoor Campaign**

    **APT Campaign**{.cve-chip}  
    **Iran-Aligned Threat Actor**{.cve-chip}  
    ---------------------------------

    Iran-aligned APT MuddyWater launched a targeted espionage campaign against Israeli organizations and Egyptian critical infrastructure. The group deployed a new custom malware toolkit centered around **MuddyViper** backdoor, using memory-only loaders (Fooder disguised as Snake game), credential stealers (CE-Notes, LP-Notes, Blub), and reverse tunneling for data exfiltration. Initial access via spear-phishing with RMM tool installers. In some cases, MuddyWater acted as initial access broker for Lyceum/OilRig.

    [:octicons-arrow-right-24: View Full Details](Week49/muddy.md)

-   ![South Korea IP Cameras](Week49/images/knpa.png)
    :material-cctv:{ .lg .middle } **Hacking of ~120,000 IP Cameras in South Korea for Sale of Intimate Content**

    **Mass IP Camera Hack**{.cve-chip}  
    **Privacy Violation**{.cve-chip}  
    ---------------------------------

    Four individuals arrested by the Korean National Police Agency for hacking over **120,000 IP cameras** in private homes and commercial facilities. Attackers exploited weak/default passwords to access video feeds, producing hundreds of sexually exploitative videos (some involving minors) sold on foreign adult websites. One suspect hacked ~63,000 cameras and sold 545 videos; another hacked ~70,000 cameras and sold 648 videos. Payment received in cryptocurrency.

    [:octicons-arrow-right-24: View Full Details](Week49/knpa.md)

-   ![OnSolve CodeRED](Week49/images/onsolve.png)
    :material-alert-circle:{ .lg .middle } **OnSolve CodeRED Ransomware Attack**

    **Ransomware Attack**{.cve-chip}  
    **INC Ransom**{.cve-chip}  
    ---------------------------------

    Crisis24's CodeRED emergency alert platform suffered a ransomware attack by INC Ransom, disrupting alert systems across multiple U.S. states. The legacy platform was compromised, exfiltrating user data (names, addresses, emails, phones, **plain-text passwords**) of hundreds of thousands of users. Municipalities lost emergency notification capabilities for floods, fires, evacuations, and other critical alerts. Ransom demand: USD $100,000. Legacy platform permanently decommissioned.

    [:octicons-arrow-right-24: View Full Details](Week49/onsolve.md)

-   ![OpenPLC ScadaBR](Week49/images/openplc.png)
    :material-bug:{ .lg .middle } **OpenPLC ScadaBR CVE-2021-26829 Active Exploitation**

    **Stored XSS**{.cve-chip}  
    **SCADA/HMI Compromise**{.cve-chip}  
    ---------------------------------

    Stored XSS vulnerability in OpenPLC ScadaBR's `system_settings.shtm` page (versions up to 1.12.4 on Windows, 0.9.1 on Linux). Actively exploited by TwoNet against honeypots mimicking water-treatment facilities. Attackers inject malicious JavaScript to manipulate HMI interfaces, disable logs/alarms, steal credentials, and create backdoor accounts—all at the web-application layer without host-level access.

    [:octicons-arrow-right-24: View Full Details](Week49/openplc.md)

-   ![Scada-LTS](Week49/images/scadalts.png)
    :material-folder-alert:{ .lg .middle } **Scada-LTS Project Import Path Traversal (CVE-2025-13791)**

    **Path Traversal**{.cve-chip}  
    **Remote Exploitation**{.cve-chip}  
    ---------------------------------

    Path traversal vulnerability in Scada-LTS (up to 2.7.8.1) Project Import component. Malicious ZIP or crafted import requests can traverse outside intended directories, allowing remote attackers to read/write sensitive configuration files, credentials, and logs. Public exploit code available. Vendor reportedly unresponsive to disclosure.

    [:octicons-arrow-right-24: View Full Details](Week49/scadalts.md)

-   ![Mercedes-Benz USA](Week49/images/benz.png)
    :material-file-document-alert:{ .lg .middle } **Mercedes-Benz USA Breach Claim by Threat Actor 'zestix'**

    **Data Breach Claim**{.cve-chip}  
    **Legal & Customer Data**{.cve-chip}  
    ---------------------------------

    Threat actor 'zestix' claims to have exfiltrated **18.3 GB of data** from Mercedes-Benz USA, including internal legal documents (litigation files across 48 U.S. states), customer PII, vendor forms, defensive strategies, billing rates, and warranty claim documents. The data is reportedly being sold on a dark-web forum for USD 5,000. **Breach claim remains unconfirmed** by MBUSA.

    [:octicons-arrow-right-24: View Full Details](Week49/benz.md)

-   ![node-forge ASN.1](Week49/images/forge.png)
    :material-lock:{ .lg .middle } **node-forge ASN.1 Validation Bypass (CVE-2025-12816)**

    **Cryptographic Verification Bypass**{.cve-chip}  
    **Integrity Compromise**{.cve-chip}  
    ---------------------------------

    A desynchronization bug in node-forge's ASN.1 validator (asn1.validate) can allow malformed ASN.1 structures (e.g., PKCS#12, certificates) to be treated as valid, bypassing MAC/signature/certificate checks and risking forged credentials or package tampering.

    [:octicons-arrow-right-24: View Full Details](Week49/forge.md)

-   ![Contagious Interview npm](Week49/images/npm.png)
    :material-package:{ .lg .middle } **Contagious Interview (2025 npm-registry wave)**

    **Supply-Chain / npm Registry Campaign**{.cve-chip}  
    **Loader Malware (OtterCookie / BeaverTail merge)**{.cve-chip}  
    ---------------------------------

    197 malicious npm packages added to the registry (≈31,000 downloads). Packages act as loaders that fetch OtterCookie payloads from Vercel/GitHub after developers install or run them, compromising developer machines and CI pipelines.

    [:octicons-arrow-right-24: View Full Details](Week49/npm.md)
    
</div>
