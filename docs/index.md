---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![Taiwan](2026/Week18/images/Taiwan.png)

    **Student Hacked Taiwan High-Speed Rail to Trigger Emergency Brakes**

    **OT Security**{.cve-chip} **TETRA Radio Spoofing**{.cve-chip} **Rail Infrastructure**{.cve-chip}

    A student used SDR equipment and cloned radios to inject a forged "General Alarm" onto Taiwan High Speed Rail's TETRA network, halting four trains for 48 minutes. The attack required no software exploit — static TETRA parameters unchanged for 19 years allowed a decoded beacon clone to bypass all seven verification layers.

    [Read more](2026/Week18/Taiwan.md)

-   ![Edge](2026/Week18/images/Edge.png)

    **Microsoft Edge Stores Passwords in Process Memory, Posing Enterprise Risk**

    **Microsoft Edge**{.cve-chip} **Credential Exposure**{.cve-chip} **Enterprise Risk**{.cve-chip}

    Microsoft Edge decrypts all saved passwords into process memory at browser startup and keeps them resident in cleartext. Any attacker who reaches admin/SYSTEM on the endpoint can dump Edge memory and recover every stored credential — Microsoft confirmed this is "by design" with no CVE or fix planned.

    [Read more](2026/Week18/Edge.md)

</div>