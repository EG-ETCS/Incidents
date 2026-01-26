# GeoServer XXE Vulnerability Exploitation (CVE-2025-58360)

**XML External Entity (XXE)**{.cve-chip}  
**Unauthenticated File Access**{.cve-chip}  
**Critical Severity**{.cve-chip}

## Overview

The incident centers on an **unauthenticated XML External Entity (XXE)** vulnerability in **OSGeo GeoServer**, an open-source platform for publishing and sharing geospatial data (WMS services). The flaw is triggered in the **"/geoserver/wms" GetMap endpoint**, where crafted XML input isn't safely validated, allowing attackers to define external entities that can access files or be abused for network probing.

This vulnerability poses a **significant risk to U.S. civilian agencies** and has been added to **CISA's Known Exploited Vulnerabilities (KEV) catalog**, with active exploitation confirmed in the wild.

## Technical Specifications

| **Attribute**         | **Details**                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| **CVE ID**            | CVE-2025-58360                                                              |
| **Vulnerability Type**| XML External Entity (XXE) Reference (CWE-611)                               |
| **CVSS Score**        | **9.8 (Critical)**                                                          |
| **Affected Product**  | OSGeo GeoServer                                                             |
| **Affected Versions** | Prior to 2.25.6; 2.26.0 through 2.26.1                                      |
| **Patched Versions**  | 2.25.6, 2.26.2, 2.27.0, 2.28.0, 2.28.1                                      |
| **Attack Vector**     | Network (unauthenticated)                                                   |
| **Authentication**    | None required                                                               |
| **Exploitability**    | Active exploitation confirmed                                               |
| **Exposed Instances** | Over 14,000 GeoServer instances exposed online                              |
| **CISA Deadline**     | Federal agencies must patch by **January 1, 2026** (BOD 22-01)             |

![](images/geoserver1.png)

## Technical Details

### Vulnerability Classification
- **CVE**: CVE-2025-58360
- **Vulnerability type**: **Improper Restriction of XML External Entity (XXE) Reference** (CWE-611)

### Affected Versions
- GeoServer versions **prior to 2.25.6**
- Versions **2.26.0 through 2.26.1**

### Patched Versions
Fixed in:

- **2.25.6**
- **2.26.2**
- **2.27.0**
- **2.28.0**
- **2.28.1**

### Exploit Vectors

The vulnerability enables three primary attack vectors:

1. **Arbitrary File Access** via crafted XML
    - Read sensitive files on the server
    - Access configuration files, credentials, etc.

2. **Server-Side Request Forgery (SSRF)**
    - Probe internal networks
    - Map infrastructure
    - Access internal services

3. **Denial of Service (DoS)**
    - Exhaust resources
    - Cause service disruption

## Attack Scenario

1. **Target Identification**: A remote attacker identifies an internet-facing GeoServer instance (over 14,000 exposed online).

2. **Malicious Request**: Attacker sends a **malicious XML request** to the GeoServer `/geoserver/wms` **GetMap endpoint**.

3. **XXE Processing**: Because GeoServer did not properly restrict or sanitize XML external entity references, the server processes the external entity.

4. **Exploitation**: This allows the attacker, **without authentication**, to:
    - **Access sensitive files** on the server (e.g., system configs or credentials)
    - Trigger **server-side requests to internal systems (SSRF)**
    - Potentially cause **resource exhaustion (DoS)**

5. **Scale**: Automated scanners and exploit tooling can target exposed internet-facing GeoServer instances **at scale**.

## Impact Assessment

=== "Data Exposure"
    * **Sensitive information** on affected servers may be accessed
    * Configuration files
    * Credentials
    * System files
    * Geospatial data

=== "Infrastructure Probing"
    * **Internal networks** could be mapped via SSRF
    * Discovery of internal services
    * Reconnaissance for further attacks

=== "Service Disruption"
    * **DoS impacts availability**
    * Resource exhaustion
    * Service degradation or complete outage

=== "Federal Agency Risk"
    * **CISA sees significant risk** to U.S. civilian agencies
    * Mandates patching by **January 1, 2026**
    * Part of Binding Operational Directive (BOD) 22-01

=== "Widespread Exposure"
    * Over **14,000 GeoServer instances** are exposed online
    * **Increasing attack surface**
    * Global reach of vulnerable systems

## Mitigations

### 🔄 Apply Vendor Patches (CRITICAL)

**Upgrade to a fixed GeoServer version:**

- **2.25.6+** (for 2.25.x series)
- **2.26.2+** (for 2.26.x series)
- **2.27.0+** (for 2.27.x series)
- **2.28.0** or **2.28.1** (for 2.28.x series)

!!! danger "Federal Agency Requirement"
    U.S. Federal civilian agencies **must patch by January 1, 2026** per CISA BOD 22-01.

### 🔒 Restrict Access

- **Limit exposure** of the `/geoserver/wms` endpoint via:
    - Firewall rules
    - Network access controls
    - VPN requirements
- Do not expose GeoServer directly to the internet unless absolutely necessary

### 📊 Monitor Logs

- Watch for:
    - **Unusual XML payloads**
    - External entity references in requests
    - SSRF patterns (internal IP access attempts)
    - Unexpected file access
    - DoS indicators (resource exhaustion)

### 🏗️ Harden XML Parsers and Services

- **Disable external entity processing** in XML parsers
- Implement **strict XML validation**
- Use safe XML parsing libraries
- Apply principle of least privilege to XML processing

### 🌐 Network Segmentation

- **Isolate GeoServer instances** from sensitive internal networks
- Implement network segmentation
- Restrict outbound connections from GeoServer
- Limit access to internal resources

### 🔍 Detection & Response

#### Indicators of Compromise (IoCs)
- Unusual XML requests to `/geoserver/wms`
- Requests containing external entity definitions
- Access to unexpected file paths
- Outbound connections to internal IPs
- Resource exhaustion patterns

#### Response Actions
If exploitation is suspected:

1. **Isolate affected systems** immediately
2. Review logs for evidence of file access or SSRF
3. Check for unauthorized data exfiltration
4. Assess what internal systems may have been probed
5. Reset credentials that may have been exposed
6. Conduct forensic analysis

## Resources & References

!!! info "Official Advisories & CISA"
    * [CISA orders feds to patch actively exploited Geoserver flaw](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-actively-exploited-geoserver-flaw/)
    * [CISA Known Exploited Vulnerabilities Catalog - CVE-2025-58360](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2025-58360)
    * [NVD - CVE-2025-58360](https://nvd.nist.gov/vuln/detail/cve-2025-58360)

!!! warning "Vulnerability Details & Analysis"
    * [CISA Flags Actively Exploited GeoServer XXE Flaw in Updated KEV Catalog](https://thehackernews.com/2025/12/cisa-flags-actively-exploited-geoserver.html)
    * [Recent GeoServer Vulnerability Exploited in Attacks - SecurityWeek](https://www.securityweek.com/recent-geoserver-vulnerability-exploited-in-attacks/amp/)
    * [U.S. CISA adds an OSGeo GeoServer flaw to its Known Exploited Vulnerabilities catalog](https://securityaffairs.com/185604/hacking/u-s-cisa-adds-an-osgeo-geoserver-flaw-to-its-known-exploited-vulnerabilities-catalog.html)

!!! tip "Detection Guidance"
    **Monitor for suspicious XML patterns in `/geoserver/wms` requests:**
    
    - Look for `<!ENTITY` declarations
    - External entity references (e.g., `file://`, `http://`, `ftp://`)
    - Requests attempting to access system files (`/etc/passwd`, `C:\Windows\win.ini`)
    - SSRF patterns targeting internal IP ranges (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
    
    **Log Analysis:**
    ```
    Check GeoServer logs for:
    - Unusual GetMap requests
    - XML parsing errors
    - File access exceptions
    - Outbound connection attempts to internal IPs
    ```