---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![recoverpoint](2026/Week7/images/recoverPoint.png)

    **Dell RecoverPoint for Virtual Machines Zero-Day Exploitation (CVE-2026-22769)**

    **CVE-2026-22769**{.cve-chip} **Zero-Day**{.cve-chip} **Hardcoded Credentials**{.cve-chip} **Backup Infrastructure**{.cve-chip} **China-Linked**{.cve-chip}

    A zero-day in Dell RecoverPoint for Virtual Machines allowed attackers to authenticate using embedded hardcoded credentials and gain full administrative access to appliances. The activity was attributed to a China-linked cluster (UNC6201) focused on long-term intelligence collection rather than disruptive ransomware.

    Post-exploitation, operators deployed web shells and C# backdoors (GRIMBOLT, BRICKSTORM variants), created temporary "ghost" virtual NICs for stealth pivoting, and used the appliance as a bridge into VMware environments and internal networks.

    [:octicons-arrow-right-24: Read more](2026/Week7/recoverPoint.md)

-   ![keenadu](2026/Week7/images/keenadu.png)

    **Keenadu — An Android Firmware-Embedded Backdoor Malware**

    **Supply Chain Compromise**{.cve-chip} **Android Backdoor**{.cve-chip} **Firmware-Level**{.cve-chip} **Preinstalled Malware**{.cve-chip}

    Keenadu is a sophisticated backdoor malware pre-installed in Android firmware due to a supply-chain compromise. It embeds into core system components, loads into every app process via Zygote, and bypasses Android sandboxing while persisting across factory resets.

    Operators can deliver additional modules for ad fraud, surveillance, or data theft. Infection spreads through compromised firmware images, signed OTA updates, and modified system apps, with 13,000+ devices reportedly affected worldwide.

    [:octicons-arrow-right-24: Read more](2026/Week7/keenadu.md)

  </div>
