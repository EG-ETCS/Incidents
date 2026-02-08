# Incident Documentation Template

## Template Structure

Your incident markdown files follow this consistent structure:

```markdown
# [Title/Name of Vulnerability or Incident]

**CVE-XXXX-XXXXX**{.cve-chip}  
**[Attack Type/Category]**{.cve-chip}  
**[Additional Category]**{.cve-chip}

## Overview
[Detailed description of the vulnerability/incident, what it does, and why it matters]

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **CVE ID** | CVE-XXXX-XXXXX |
| **Vulnerability Type** | [Type with CWE if applicable] |
| **CVSS Score**| [0.0 (High/Critical)] |
| **Attack Vector** | [Network/Local/Physical] |
| **Authentication** | [None/Low/High] |
| **Complexity** | [Low/Medium/High] |
| **User Interaction** | [Required/Not Required] |
| **Affected Versions** | [Version numbers] |

## Affected Products
- [Product name and version]
- [Serial numbers if applicable]
- [Firmware versions]
- [Status: Active/EoL]

## Attack Scenario
1. [Step 1 of attack]
2. [Step 2 of attack]
3. [Step 3 of attack]
4. [Step 4 of attack]
5. [Step 5 of attack]

## Impact Assessment

=== "Integrity"
    * [Impact point 1]
    * [Impact point 2]
    * [Impact point 3]

=== "Confidentiality"
    * [Impact point 1]
    * [Impact point 2]
    * [Impact point 3]

=== "Availability"
    * [Impact point 1]
    * [Impact point 2]
    * [Impact point 3]

## Mitigation Strategies

### Immediate Actions
- [Action 1]
- [Action 2]
- [Action 3]

### Short-term Measures
- [Measure 1]
- [Measure 2]
- [Measure 3]

### Monitoring & Detection
- [Monitoring step 1]
- [Monitoring step 2]
- [Monitoring step 3]

### Long-term Solutions
- [Solution 1]
- [Solution 2]
- [Solution 3]

## Resources and References

!!! info "Official Documentation"
    - [Link 1](URL)
    - [Link 2](URL)
    - [Link 3](URL)
```
---

*Last Updated: month day, year* 

---

## How to Use This Template

Provide me with data in **table format** like this:

### Example Input Table:

| Field | Value |
|-------|-------|
| **Title** | ABB FLXeon Controllers Vulnerabilities |
| **CVE IDs** | CVE-2024-48842, CVE-2024-48851, CVE-2025-10205 |
| **Chip Tags** | CVE-2024-48842, CVE-2024-48851, Remote Code Execution |
| **Overview** | Multiple high-severity vulnerabilities in ABB's FLXeon controllers allowing remote code execution... |
| **Vendor** | ABB |
| **Products** | FBXi, FBVi, FBTi, CBXi Controllers |
| **Firmware Versions** | ≤ 9.3.5 |
| **Vulnerability Type** | Hard-Coded Credentials (CWE-798), RCE |
| **Attack Vector** | Network |
| **Authentication** | May be bypassed |
| **Complexity** | Low |
| **User Interaction** | Not required |
| **CVSS Score** | 8.7 (High) |
| **Affected Products List** | FBXi-8R8-X96, FBXi-X256, FBVi-2U4-4T |
| **Attack Step 1** | Attacker scans for vulnerable devices |
| **Attack Step 2** | Exploits hard-coded credentials |
| **Attack Step 3** | Gains full system access |
| **Attack Step 4** | Executes arbitrary code |
| **Attack Step 5** | Maintains persistence |
| **Impact - Integrity** | Full compromise of device configuration; Unauthorized modification; Alteration of settings |
| **Impact - Confidentiality** | Access to sensitive data; Exposure of credentials; System information disclosure |
| **Impact - Availability** | Service disruption; System downtime; Operational failures |
| **Mitigation - Immediate** | Apply security patches; Isolate affected devices; Monitor for exploitation |
| **Mitigation - Short-term** | Implement network segmentation; Enable logging; Review access controls |
| **Mitigation - Monitoring** | Deploy IDS/IPS; Monitor network traffic; Alert on suspicious activity |
| **Resources** | https://link1.com; https://link2.com; https://link3.com |
| **Filename** | abb-fbxi.md |
| **Week** | Week46 |

---

## Simplified Table Format

You can also provide a **simpler table** and I'll fill in the details:

| Field | Value |
|-------|-------|
| Title | [Your Title] |
| CVE | CVE-XXXX-XXXXX |
| Tags | Tag1, Tag2, Tag3 |
| Overview | [Brief description] |
| Vendor | [Vendor name] |
| Product | [Product name] |
| Attack Vector | Network/Local |
| CVSS | 9.8 |
| Attack Steps | Step 1; Step 2; Step 3; Step 4; Step 5 |
| Impacts | Integrity impacts; Confidentiality impacts; Availability impacts |
| Mitigations | Immediate actions; Short-term; Monitoring; Long-term |
| Resources | URL1; URL2; URL3 |
| Week | Week51 |
| Filename | your-file.md |

---

## Alternative: Key-Value Format

```
Title: Google Chrome V8 Zero-Day
CVE: CVE-2025-13223
Tags: Remote Code Execution, Browser Exploitation, Zero-Day
Overview: A critical type-confusion vulnerability in Chrome's V8 engine...
Vendor: Google
Product: Chrome
Versions: < 142.0.7444.175
Attack Vector: Remote
Complexity: Low
CVSS: 9.8
Attack Steps:
  1. Attacker creates malicious webpage
  2. Victim visits page
  3. V8 engine triggered
  4. Code execution achieved
  5. System compromised
Impacts - Integrity: Session manipulation; Credential theft; Token compromise
Impacts - Confidentiality: Browsing history access; Data exfiltration; Credential exposure
Impacts - Availability: Browser crash; Service disruption; DoS
Mitigations - Immediate: Update Chrome; Enable auto-updates; Restart browser
Mitigations - Monitoring: Monitor for CVE; Check Chrome version; Alert on exploitation
Resources: https://chromium.org; https://cisa.gov
Week: Week47
Filename: chrome-v8-zero-day.md
```

---

## Instructions

1. **Provide your data** in any of the formats above
2. I will **generate a complete markdown file** following your established structure
3. The file will be **created in the specified week folder** with proper formatting, chips, tabs, and sections

Just paste your table or key-value data, and I'll create the markdown file for you!
