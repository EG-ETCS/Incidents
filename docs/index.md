---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![protobuf](2026/Week4/images/protobuf.png)

    **Google Protocol Buffers JSON Parsing Denial-of-Service Vulnerability**

    **CVE-2026-0994**{.cve-chip} **Denial-of-Service**{.cve-chip} **JSON Parsing**{.cve-chip} **Python Protobuf**{.cve-chip} **Recursion Bypass**{.cve-chip}

    A high-severity vulnerability in Google Protocol Buffers (protobuf) Python implementation allows attackers to crash applications by sending specially crafted JSON payloads. By abusing deeply nested protobuf Any message types, attackers can bypass built-in recursion limits, leading to uncontrolled recursion and service termination.
    
    The flaw exists in the json_format.ParseDict() function where nested Any messages bypass the recursion counter, causing stack exhaustion and RecursionError. No authentication is required, enabling remote exploitation and persistent denial-of-service attacks against any service parsing untrusted JSON with Python protobuf.

    [:octicons-arrow-right-24: Read more](2026/Week4/protobuf.md)

-   ![office](2026/Week4/images/office.png)

    **Microsoft Office Security Feature Bypass Vulnerability**

    **CVE-2026-21509**{.cve-chip} **Security Feature Bypass**{.cve-chip} **COM/OLE Processing**{.cve-chip} **User Interaction**{.cve-chip} **Zero-Day**{.cve-chip}

    A critical security feature bypass vulnerability in Microsoft Office allows attackers to circumvent built-in security controls designed to block dangerous COM/OLE objects embedded in Office files. The flaw affects Office 2016, 2019, LTSC 2021/2024, and Microsoft 365 Apps for Enterprise.
    
    Exploitation requires user interaction to open a malicious Office document. Once opened, the vulnerability allows attackers to bypass Office security mitigations, potentially leading to unauthorized code execution, malware deployment, data theft, or system compromise. The vulnerability is actively exploited in the wild.

    [:octicons-arrow-right-24: Read more](2026/Week4/office.md)

-   ![winrar](2026/Week4/images/winrar.png)

    **WinRAR Path Traversal Vulnerability**

    **CVE-2025-8088**{.cve-chip} **Path Traversal**{.cve-chip} **Arbitrary Code Execution**{.cve-chip} **Active Exploitation**{.cve-chip} **State-Sponsored**{.cve-chip}

    A critical path traversal flaw in WinRAR allows attackers to craft malicious RAR archives that extract executable payloads to arbitrary locations on the victim's file system, such as Windows Startup folders. The vulnerability affects WinRAR versions up to 7.12 and is actively exploited by both state-aligned threat actors and cybercriminals.
    
    Exploitation occurs through spear-phishing campaigns delivering crafted RAR files that abuse NTFS Alternate Data Streams to bypass extraction boundaries. Once opened, malware is automatically placed in startup directories and executes without further user interaction, establishing persistent backdoor access.

    [:octicons-arrow-right-24: Read more](2026/Week4/winrar.md)

-   ![grist](2026/Week4/images/grist.png)

    **Critical Grist-Core Vulnerability Allows RCE Attacks via Spreadsheet Formulas**

    **CVE-2026-24002**{.cve-chip} **Remote Code Execution**{.cve-chip} **Sandbox Escape**{.cve-chip} **Cellbreak**{.cve-chip} **Pyodide**{.cve-chip}

    A critical vulnerability in Grist-Core allows attackers to achieve remote code execution through malicious Python formulas in spreadsheets. The "Cellbreak" flaw enables crafted formulas to escape the Pyodide WebAssembly sandbox and run arbitrary OS commands or host JavaScript, collapsing the boundary between spreadsheet logic and server execution.
    
    The vulnerability stems from improper sandbox isolation allowing class hierarchy traversal and access to dangerous modules like ctypes. Once escaped, attackers gain complete control over the server process, enabling data theft, credential extraction, and lateral movement within networks.

    [:octicons-arrow-right-24: Read more](2026/Week4/grist.md)

-   ![vm2](2026/Week4/images/vm2.png)

    **vm2 Sandbox Escape Vulnerability**

    **CVE-2026-22709**{.cve-chip} **Sandbox Escape**{.cve-chip} **Arbitrary Code Execution**{.cve-chip} **Node.js**{.cve-chip} **Promise Bypass**{.cve-chip}

    A critical sandbox escape vulnerability in vm2, a popular Node.js library for executing JavaScript in isolated contexts, allows attackers to bypass sandbox restrictions and execute arbitrary code on the host system. The flaw stems from incomplete sanitization of Promise callbacks where globalPromise.prototype.then and catch are not properly sanitized.
    
    Attackers can leverage async functions that return globalPromise objects to attach malicious callbacks, access native constructors, and invoke modules like child_process to execute arbitrary code with full Node.js process privileges. This affects CI/CD pipelines, code execution services, plugin systems, and developer tooling.

    [:octicons-arrow-right-24: Read more](2026/Week4/vm2.md)


</div>
