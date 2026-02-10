# React2Shell (CVE-2025-55182)
![React2Shell](images/react2shell.png)

**Remote Code Execution**{.cve-chip}  
**Unsafe Deserialization**{.cve-chip}  
**Critical Severity**{.cve-chip}

## Overview

CVE-2025-55182 is a **severe vulnerability** in the server-side part of React, specifically in its **React Server Components (RSC) / "Flight" protocol**. The bug lies in **unsafe deserialization** — the mechanism by which React reconstructs objects sent from client to server. An attacker can craft a malicious HTTP request whose payload, when deserialized by React on the server, **executes arbitrary code**.

Affected libraries include:

    - `react-server-dom-webpack`
    - `react-server-dom-parcel`
    - `react-server-dom-turbopack` (versions 19.0, 19.1.0, 19.1.1, 19.2.0)

Frameworks / tools built on React that bundle or embed those packages, most notably **Next.js**.

Even applications that don't explicitly leverage "Server Functions" endpoints may still be vulnerable, if they support React Server Components.

## Technical Specifications

| **Attribute**         | **Details**                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| **CVE ID**            | CVE-2025-55182                                                              |
| **Also Known As**     | React2Shell                                                                 |
| **Vulnerability Type**| Unsafe Deserialization → Remote Code Execution (RCE)                        |
| **Affected Libraries**| react-server-dom-webpack, react-server-dom-parcel, react-server-dom-turbopack |
| **Affected Versions** | 19.0, 19.1.0, 19.1.1, 19.2.0                                                |
| **Affected Frameworks**| Next.js (multiple versions)                                                |
| **Attack Vector**     | Network (single HTTP request)                                               |
| **Authentication**    | None required (unauthenticated RCE)                                         |
| **Exploitability**    | Public PoC available, active exploitation confirmed                         |
| **Success Rate**      | Near 100% (high-fidelity exploitation reported)                             |
| **Exposed Attack Surface** | ~39% of cloud environments (per Wiz study)                             |

![](images/react2shell1.png)

## Technical Details

### Vulnerability Root Cause
- **Unsafe deserialization** of attacker-controlled payloads in React's **"Flight" protocol**
- Internal mechanism for serializing/deserializing data sent between client and server in RSC

### Trigger Mechanism
- A **single HTTP request** with malicious payload can trigger **remote code execution** on the server
- **Without authentication or privileges**

### Affected Components/Libraries
- `react-server-dom-webpack`
- `react-server-dom-parcel`
- `react-server-dom-turbopack`
- Frameworks bundling them (e.g., **Next.js**)

### Patched Versions

#### React Packages
Fixed in:

  - **19.0.1**
  - **19.1.2**
  - **19.2.1**

#### Next.js
Fixed in several versions depending on series:

  - 15.0.5
  - 15.1.9
  - 15.2.6
  - 15.3.6
  - 15.4.8
  - 15.5.7
  - 16.0.7

### Exploitability Status
- **Public proof-of-concept (PoC) code** is now circulating
- Multiple security firms report **high-fidelity exploitation** with **near 100% success rate**
- **Active exploitation confirmed** in the wild

![](images/react2shell2.png)

## Attack Scenario

1. **Target Identification**: Attacker scans the internet for publicly exposed web servers running vulnerable versions of React/Next.js (or other impacted frameworks). According to initial telemetry, **~39% of cloud environments** are vulnerable.

2. **Malicious Request**: Once a target is found, attacker sends a **specially crafted HTTP request** (malformed payload designed to exploit deserialization bug) to a server endpoint that handles React Server Components / Server Functions.

3. **Code Execution**: Because of unsafe deserialization, the payload triggers execution of **arbitrary code on the server**. The attacker gains **remote code execution (RCE)**, potentially at the server's privilege level.

4. **Post-Exploitation**: With RCE, attacker can perform malicious actions:
    - Install web shells
    - Steal environment variables/credentials
    - Exfiltrate data
    - Pivot within networks
    - Deploy malware
   
    Early reports show:

    - Theft of cloud credentials
    - Filesystem access
    - Attempts to install malicious implants

5. **Scalability**: Because exploitation requires only **internet access and no authentication**, this scenario is **highly scalable** and "low bar" for attackers.

## Impact Assessment

=== "Scale & Ubiquity"
    * **Potentially massive**: given the ubiquity of React and related frameworks (including Next.js)
    * A **huge portion of web applications globally** are affected
    * ~39% of cloud environments contain vulnerable React/Next.js instances (per Wiz estimate)

=== "Attack Severity"
    * **Remote, unauthenticated takeover**
    * Attacker can gain **full server-side code execution**
    * Access to environment, credentials
    * Leading to:
        - Data breach
        - Persistent backdoors
        - Lateral movement
        - Cloud resource abuse

=== "Active Exploitation"
    * **Widespread scanning / active exploitation**
    * Security intelligence shows that **multiple threat actor groups** (including alleged state-linked actors) have already begun exploiting the vulnerability
    * Targeting a variety of sectors:
        - Cloud services
        - Corporate
        - Government
    * Across multiple regions

=== "Attack Surface"
    * **Large exposed attack surface**
    * Single HTTP request can compromise server
    * No authentication required
    * High success rate exploitation

## Mitigations

### 🔄 Patch Immediately
**Upgrade affected React Server Component packages** to fixed versions:
- `react-server-dom-webpack/parcel/turbopack` → **19.0.1, 19.1.2, 19.2.1**

**Update Next.js** to the patched fixed versions:
- 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7

### 🛡️ Web Application Firewall (WAF)
- Use **WAFs as a stop-gap defense** while patching
- Major cloud providers and WAF vendors have already rolled out rules to block exploit attempts

### 🔍 Audit and Monitor
- **Scan all applications** (especially internet-facing) for vulnerable dependencies
- Review server logs for suspicious requests
- Watch for:
    - Unexpected process spawning
    - Web shells
    - Anomalous outbound connections
    - Credential access

### 🏗️ Defense-in-Depth
- **Restrict access** to services
- **Minimize exposure** of server-side React usage
- **Limit privileges**
- Enforce **least-privilege** on secrets/credentials
- **Separate sensitive services**

### 📊 Vulnerability Scanning
- Use vulnerability-scanning tools that detect presence of React2Shell-vulnerable packages or Next.js versions
- Many vendors (cloud or security-tool providers) have released **detection plugins**

### 🚨 Incident Response
- If compromise is suspected:
    - Isolate affected systems
    - Review logs for evidence of exploitation
    - Reset credentials and secrets
    - Conduct forensic analysis

## Resources & References

!!! info "Official Advisories & Analysis"
    * [Critical Security Vulnerability in React Server Components – React](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
    * [CVE-2025-55182 (React2Shell): Remote code execution in React Server Components and Next.js | Datadog Security Labs](https://securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components/)
    * [React2Shell RCE (CVE-2025-55182) Next.js (CVE-2025-66478) | Tenable®](https://www.tenable.com/blog/react2shell-cve-2025-55182-react-server-components-rce)
    * [CVE-2025-55182 vulnerability in React and Next.js | Kaspersky official blog](https://www.kaspersky.com/blog/react4shell-vulnerability-cve-2025-55182/54915/)

!!! warning "Active Exploitation & Threat Intelligence"
    * [Critical React2Shell Flaw Added to CISA KEV After Confirmed Active Exploitation](https://thehackernews.com/2025/12/critical-react2shell-flaw-added-to-cisa.html)
    * [React2Shell flaw exploited to breach 30 orgs, 77k IP addresses vulnerable](https://www.bleepingcomputer.com/news/security/react2shell-flaw-exploited-to-breach-30-orgs-77k-ip-addresses-vulnerable/)
    * [Chinese Hackers Have Started Exploiting the Newly Disclosed React2Shell Vulnerability](https://thehackernews.com/2025/12/chinese-hackers-have-started-exploiting.html)
    * [React2Shell: In-the-Wild Exploitation Expected for Critical React Vulnerability - SecurityWeek](https://www.securityweek.com/react2shell-in-the-wild-exploitation-expected-for-critical-react-vulnerability/)
    * [React.js Hit by Maximum-Severity 'React2Shell' Vulnerability - Infosecurity Magazine](https://www.infosecurity-magazine.com/news/reactjs-hit-by-react2shell/)
    * [Experts warn this 'worst case scenario' React vulnerability could soon be exploited - so patch now | TechRadar](https://www.techradar.com/pro/security/experts-warn-this-worst-case-scenario-react-vulnerability-could-soon-be-exploited-so-patch-now)

!!! danger "Critical Priority"
    This vulnerability is being **actively exploited** in the wild by multiple threat actors, including state-linked groups. **Immediate patching is critical** for all React/Next.js deployments.