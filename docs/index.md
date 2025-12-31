---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![Critical SmarterMail Vulnerability](Week53/images/smartermail.png)

    :material-email:{ .lg .middle } **Critical SmarterMail Arbitrary File Upload / Remote Code Execution Vulnerability**

    **CVE-2025-52691**{.cve-chip} 
    **CVSS 10.0**{.cve-chip} 
    **RCE / Arbitrary File Upload**{.cve-chip}

    A critical unauthenticated arbitrary file upload vulnerability in SmarterTools SmarterMail (Build 9406 and earlier) can allow remote attackers to upload and execute files, leading to full server compromise. Update to Build 9413 or later immediately.

    [:octicons-arrow-right-24: View Full Details](Week53/smartermail.md)

-   ![MongoDB Memory Disclosure](Week53/images/mongo.png)

    :material-database:{ .lg .middle } **MongoBleed — MongoDB Memory Disclosure (CVE-2025-14847)**
    
    **CVE-2025-14847**{.cve-chip} 
    **Memory Disclosure**{.cve-chip} 
    **Pre-auth Network Leak**{.cve-chip}
    
    Critical pre-auth memory disclosure in MongoDB allowing unauthenticated attackers to extract heap memory via specially crafted compressed messages. Patch to fixed versions and restrict network exposure.
    
    [:octicons-arrow-right-24: View Full Details](Week53/mongo.md)

</div>
