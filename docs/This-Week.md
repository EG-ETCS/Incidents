---
hide:
  - navigation
  - toc
---

# This Week's Security Incidents
 
<div class="grid cards" markdown>

-   ![GeoServer](Week51/images/geoserver.png)
    :material-earth:{ .lg .middle } **GeoServer XXE Vulnerability Exploitation (CVE-2025-58360)**

    **XML External Entity (XXE)**{.cve-chip}  
    **Unauthenticated File Access**{.cve-chip}  
    ---------------------------------

    Critical unauthenticated XXE vulnerability in OSGeo GeoServer's `/geoserver/wms` GetMap endpoint. Crafted XML enables **arbitrary file access, SSRF, and DoS** without authentication. Affects versions before 2.25.6 and 2.26.0-2.26.1. **Active exploitation confirmed** - Added to CISA KEV. Over **14,000 instances exposed** online. **Federal agencies must patch by Jan 1, 2026**. Upgrade to 2.25.6+, 2.26.2+, 2.27.0+, or 2.28.1+ immediately. CVSS 9.8 (Critical).

    [:octicons-arrow-right-24: View Full Details](Week51/geoserver.md)
    
-   ![Sierra Wireless](Week51/images/sierra.png)
    :material-router-wireless:{ .lg .middle } **CVE-2018-4063 Sierra Wireless AirLink ALEOS Remote Code Execution**

    **Remote Code Execution**{.cve-chip}  
    **Unrestricted File Upload**{.cve-chip}  
    ---------------------------------

    Vulnerability in Sierra Wireless AirLink ALEOS router firmware's web management interface (`upload.cgi`) allows authenticated attackers to upload arbitrary executable files. Attackers can replace system scripts and execute code as **root**, gaining full device control. Affects ES450 and related models in **OT/ICS environments** (utilities, transportation). **Active exploitation confirmed** - Added to CISA KEV. **Patch to latest ALEOS firmware** immediately, change default credentials, and restrict management interface access. CVSS 8.8 (High).

    [:octicons-arrow-right-24: View Full Details](Week51/sierra.md)

</div>
