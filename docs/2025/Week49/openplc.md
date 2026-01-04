# OpenPLC ScadaBR CVE-2021-26829 Active Exploitation

**Stored XSS**{.cve-chip}  
**SCADA/HMI Compromise**{.cve-chip}  
**Active Exploitation**{.cve-chip}

## Overview

CVE-2021-26829 is a stored XSS vulnerability in OpenPLC ScadaBR's `system_settings.shtm` page. Affected versions are up to **1.12.4 on Windows**, and up to **0.9.1 on Linux**.

The flaw allows an attacker who can reach the interface (e.g., via default or weak credentials) to inject malicious JavaScript that will be stored. Anytime an operator/admin visits that page, the script executes in their browser context, potentially manipulating the HMI interface, stealing credentials/sessions, or altering configuration.

## Technical Specifications

| **Attribute**           | **Details**                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| **CVE ID**              | CVE-2021-26829                                                              |
| **Vulnerability Type**  | Stored Cross-Site Scripting (CWE-79)                                        |
| **Affected Component**  | `system_settings.shtm` page in OpenPLC ScadaBR                              |
| **Affected Versions**   | Up to 1.12.4 (Windows), up to 0.9.1 (Linux)                                 |
| **Attack Vector**       | Network (Web Interface)                                                     |
| **Authentication**      | Required (often default/weak credentials)                                   |
| **Target Environment**  | SCADA/HMI systems in critical infrastructure                                |

## Technical Details

### Vulnerability Mechanism
- **Trigger**: User-supplied input not properly sanitized or filtered before persistent storage/rendering, leading to script injection in the backend content.
- **Storage**: Malicious JavaScript is stored in the application and executed whenever an authenticated user visits the vulnerable page.

### Attack Capabilities
When malicious script executes in the context of an authenticated user (e.g., HMI operator/admin), possibilities include:
- Session hijacking
- Credential theft
- Unauthorized UI changes (e.g., hiding or modifying panels or parameters)
- Disabling logs/alarms
- Redirecting to attacker servers
- Control over the SCADA interface / HMI elements

All without needing OS-level exploits or host-level privilege escalation.

## Attack Scenario

### Reported Case: TwoNet Attack (September 2025)

In September 2025, **TwoNet** attacked a honeypot configured to mimic a water-treatment facility running ScadaBR. The chain observed by security researchers went as follows:

1. **Initial Access**: Use of default credentials to log in.
2. **Persistence**: Creation of a new user account named **"BARLATI"** for persistence.
3. **Exploitation**: Exploitation of CVE-2021-26829 to inject malicious script.
4. **Impact**:
    - Defacement of the HMI login page (e.g., a pop-up "Hacked by Barlati")
    - Modification of system settings to disable HMI logs and alarms
5. **Scope**: According to the report, they did not escalate privileges to the underlying host: all abuse stayed at the web-application layer (HMI).

Because the target was a **honeypot (a decoy)**, it's unclear whether a real industrial facility has been compromised — but the behavior demonstrates that even "just" XSS can lead to meaningful OT impact if exploited.

![](images/openplc1.png)

## Impact Assessment

=== "HMI Manipulation"
    * Potential compromise of SCADA HMI interface
    * Attackers can manipulate what operators see (e.g., sensor values, alarms)
    * Possibly causing incorrect operator decisions

=== "Stealth & Persistence"
    * Disabling of logs/alarms: making malicious changes stealthy
    * Impeding detection or forensic audit
    * Session hijacking, credential theft or persistence (e.g., backdoor accounts)
    * Leading to long-term unauthorized access

=== "Operational & Safety Risk"
    * In a real deployment, could lead to disruption of industrial processes
    * Safety hazards, loss of availability or integrity of control systems
    * SCADA systems often control critical infrastructure (water, utilities, power)
    * Potential real-world impact could be **severe**

=== "Real-World Threat"
    * Even though publicly documented exploitation is only for a honeypot
    * The fact that the flaw is in the wild, combined with scanning and detection efforts (by actors like TwoNet)
    * Suggests a **real risk** to any unpatched ScadaBR instance exposed or reachable

## Mitigations

### 🔄 Patching
- Apply the vendor-provided patch / fix
- **Upgrade ScadaBR** beyond the vulnerable versions (i.e., versions later than 1.12.4 on Windows, or later than 0.9.1 on Linux)

### 🛡️ If Patching is Not Immediately Possible
- **Restrict or limit access** to the web interface (HMI)
- Limit who can reach the web UI (network segmentation, VPNs, firewall rules, internal-only access)

### 🔒 Strong Authentication
- Implement **strong credentials** (no default credentials)
- Enforce unique and strong passwords for administrators/accounts

### 🛠️ Compensating Controls
- Use **Web Application Firewalls (WAFs)** or input-validation/sanitization proxies
- Filter or block malicious script payloads if the interface must remain exposed

### 📊 Monitoring & Detection
- Monitor network logs, HMI interface access logs, and audit configuration changes
- Hunt for anomalous behavior:
  - Unexpected user creations
  - Disabling of logs/alarms
  - Unusual page modifications

### 🗑️ Decommissioning
- If possible, **decommission or replace** ScadaBR installations
- Especially if there is no longer vendor support or ability to patch

## Resources & References

!!! info "Official & Advisory Resources"
    * [CISA Adds Actively Exploited XSS Bug CVE-2021-26829 in OpenPLC ScadaBR to KEV](https://thehackernews.com/2025/11/cisa-adds-actively-exploited-xss-bug.html)
    * [NVD - CVE-2021-26829](https://nvd.nist.gov/vuln/detail/CVE-2021-26829)
    * [CVE-2021-26829 Details](https://www.cvedetails.com/cve/CVE-2021-26829)
    * [An XSS vulnerability in OpenPLC ScadaBR is being actively exploited in the wild - ZAM](https://nicolascoolman.eu/en/cisa-openplc-alerte)
    * [CVE-2021-26829 Added to CISA KEV After Active Exploitation](https://botcrawl.com/cve-2021-26829-added-to-cisa-kev-after-active-exploitation-of-openplc-scadabr/)