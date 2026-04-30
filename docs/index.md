---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![VNC](2026/Week17/images/VNC.png)

    **Internet-Exposed VNC/RDP Servers in ICS/OT Infrastructure**

    **ICS/OT Security**{.cve-chip} **Exposed Remote Access**{.cve-chip} **Critical Infrastructure**{.cve-chip}

    ~60,000 VNC servers require no authentication and ~670 are directly linked to ICS/OT systems, giving attackers trivial remote desktop access to SCADA and HMI interfaces. Combined with ~1.8 million exposed RDP servers, the attack surface enables ransomware deployment, process manipulation, and physical safety risks without exploiting any vulnerability.

    [Read more](2026/Week17/VNC.md)

-   ![GitHub](2026/Week17/images/GitHub.png)

    **Critical GitHub Vulnerability Exposed Millions of Repositories (CVE-2026-3854)**

    **CVE-2026-3854**{.cve-chip} **Remote Code Execution**{.cve-chip} **Supply Chain Risk**{.cve-chip}

    A command injection flaw in GitHub's internal `git push` pipeline allowed an attacker with ordinary push access to inject headers, override hook execution paths, and achieve RCE on backend servers. On GHES this means full instance compromise; on GitHub.com, Wiz confirmed RCE on multi-tenant storage nodes exposing millions of repositories.

    [Read more](2026/Week17/GitHub.md)

-   ![Motorcycles](2026/Week17/images/Motorcycles.png)

    **Electric Motorcycles and Scooters Bluetooth & Keyless Entry Vulnerabilities**

    **IoT Security**{.cve-chip} **Bluetooth Vulnerability**{.cve-chip} **Vehicle Security**{.cve-chip}

    Researchers found a Bluetooth pairing authentication bypass in Zero Motorcycles and a key fob replay/spoofing flaw in Yadea scooters. Attackers within range can connect without verification, upload malicious firmware, or remotely unlock and start vehicles — posing theft and rider safety risks.

    [Read more](2026/Week17/Motorcycles.md)

</div>