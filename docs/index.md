---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![Pack2TheRoot](2026/Week17/images/Pack2TheRoot.png)

    **Easily Exploitable Pack2TheRoot Linux Vulnerability Leads to Root Access**

    **CVE-2026-41651**{.cve-chip} **Pack2TheRoot**{.cve-chip} **Linux Privilege Escalation**{.cve-chip} **PackageKit TOCTOU**{.cve-chip}

    Pack2TheRoot is a high-severity PackageKit race-condition vulnerability that can let local unprivileged users run package operations as root without expected authentication.

    Given broad default PackageKit deployment, this issue significantly lowers the barrier for post-compromise escalation on Linux desktops and some shared server environments.

    [Read more](2026/Week17/Pack2TheRoot.md)

-   ![Firefox](2026/Week17/images/Firefox.png)

    **Firefox Vulnerability Allows Tor User Fingerprinting**

    **CVE-2026-6770**{.cve-chip} **Firefox/Tor Browser**{.cve-chip} **IndexedDB Privacy Flaw**{.cve-chip} **Cross-Site Linkability**{.cve-chip}

    A privacy flaw in Firefox-based browsers allowed sites to derive a stable process-lifetime identifier from IndexedDB behavior, enabling cross-site correlation without cookies.

    The issue had elevated impact for anonymity use cases, including Tor workflows, where expected session unlinkability could be weakened until patched versions were deployed.

    [Read more](2026/Week17/Firefox.md)

</div>