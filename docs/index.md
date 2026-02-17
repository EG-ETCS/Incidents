---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![ivanti](2026/Week7/images/ivanti.png)

    **CVE-2026-1340 — Ivanti Endpoint Manager Mobile (EPMM) Pre-Auth Remote Code Execution**

    **CVE-2026-1340**{.cve-chip} **CVE-2026-1281**{.cve-chip} **Remote Code Execution**{.cve-chip} **Pre-Authentication**{.cve-chip} **Zero-Day**{.cve-chip}

    A severe code-injection vulnerability in Ivanti Endpoint Manager Mobile allows unauthenticated attackers to execute arbitrary system commands via crafted HTTP requests. Actively exploited in the wild with 83% of activity linked to a single threat actor conducting mass exploitation using 300 rotating User-Agents and DNS callbacks for verification.

    Often chained with CVE-2026-1281, the vulnerability stems from improper input handling in legacy EPMM scripts. Exploitation enables complete server compromise, ransomware deployment, unauthorized control of managed mobile devices, credential theft, and lateral movement across enterprise networks. Government and enterprise breaches already reported.

    [:octicons-arrow-right-24: Read more](2026/Week7/ivanti.md)

</div>
