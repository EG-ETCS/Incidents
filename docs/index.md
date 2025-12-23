---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![Romanian Waters](Week52/images/romanian.png)
    :material-water:{ .lg .middle } **Romanian Waters Authority Ransomware Attack**

    **Ransomware**{.cve-chip}  
    **BitLocker Abuse**{.cve-chip}  
    **Critical Infrastructure**{.cve-chip}  
    **1,000 Systems**{.cve-chip}  
    ---------------------------------

    **Romanian Waters authority** (Apele Române) suffered ransomware incident compromising **~1,000 IT systems** across national and regional offices. Attackers abused **Windows BitLocker** native encryption to maliciously encrypt systems, avoiding traditional ransomware detection. Affected **GIS servers, databases, email, web, and DNS infrastructure**. Ransom note demanded contact within **7 days**. Website taken offline. **Critical OT systems remained operational** due to proper **IT/OT segregation**—dam control, flood monitoring, and water distribution unaffected. No threat actor claimed responsibility. **DNSC and Romanian Intelligence** investigating. Systems being restored from backups. **Policy: no negotiation**. Integration into national critical infrastructure cyber monitoring underway. BitLocker abuse technique requires enhanced endpoint detection.

    [:octicons-arrow-right-24: View Full Details](Week52/romanian.md)

-   ![Kimwolf Botnet](Week52/images/kimwolf.png)
    :material-robot-angry:{ .lg .middle } **Kimwolf Botnet: 1.8M Android Devices Hijacked**

    **Android Botnet**{.cve-chip}  
    **1.8M Devices**{.cve-chip}  
    **DDoS**{.cve-chip}  
    **Proxy Network**{.cve-chip}  
    ---------------------------------

    **Kimwolf botnet** compromised **~1.8 million Android devices** (smart TVs, set-top boxes, tablets) into distributed attack network. Built with **Android NDK** native code. Capabilities: **DDoS (TCP/UDP/ICMP)**, **proxy forwarding**, **reverse shell**, file management. Uses **DNS-over-TLS encryption**, **ECDSA-signed commands**, and **Ethereum Name Service (ENS)** blockchain domains (pawsatyou.eth) for resilient C2 (EtherHiding). Linked to **AISURU botnet** via shared code. Issued **~1.7 billion DDoS commands**; **96% of activity is proxy monetization**. C2 domain briefly **ranked above Google** in Cloudflare traffic. Infected via trojanized apps, insecure firmware, or **uncertified Android TV boxes**. Use certified devices, avoid sideloading, update firmware, change default passwords, disable ADB, segment IoT networks.

    [:octicons-arrow-right-24: View Full Details](Week52/kimwolf.md)

-   ![Ink Dragon APT](Week52/images/dragon.png)
    :material-shield-alert:{ .lg .middle } **China-Linked Ink Dragon APT Espionage Campaign**

    **APT Campaign**{.cve-chip}  
    **China-Linked**{.cve-chip}  
    **ShadowPad**{.cve-chip}  
    **Government Targets**{.cve-chip}  
    ---------------------------------

    **Ink Dragon** China-linked APT targeting **government and telecom networks** across Asia, South America, and Europe. Exploits **misconfigured IIS/SharePoint servers** using **ASP.NET ViewState deserialization** (predictable machine keys) for RCE. Deploys **ShadowPad backdoor** and **FINALDRAFT (Squidoor)** malware. Establishes **C2 relay network** converting compromised IIS servers into traffic-forwarding nodes blending with legitimate traffic. Harvests credentials via **LSASS dumps**, registry hive extraction. Maintains **stealthy long-term persistence** via scheduled tasks, services, firewall modifications. Exfiltrates sensitive government data. Harden IIS/SharePoint, rotate machine keys, deploy EDR, segment networks, monitor relay behavior, and reset all credentials after detection.

    [:octicons-arrow-right-24: View Full Details](Week52/dragon.md)

</div>
