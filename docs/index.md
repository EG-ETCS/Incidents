---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![RedWing](2026/Week27/images/RedWing.png)

    **RedWing Android Banking Malware-as-a-Service (MaaS)**

    **Android Banking Trojan**{.cve-chip} **Malware-as-a-Service**{.cve-chip} **Overlay Phishing**{.cve-chip} **Accessibility Abuse**{.cve-chip} **MFA Bypass**{.cve-chip}

    RedWing is a Telegram-marketed Android MaaS platform that enables criminals to run banking and crypto account-takeover campaigns via malicious APK sideloading, fake overlays, OTP interception, and Accessibility abuse to automate fraudulent transactions.

    [Read more](2026/Week27/RedWing.md)

-   ![Tenda](2026/Week27/images/Tenda.png)

    **Hidden Backdoor in Tenda Router Firmware (CVE-2026-11405)**

    **CVE-2026-11405**{.cve-chip} **Authentication Bypass**{.cve-chip} **Hardcoded Secret**{.cve-chip} **Router Backdoor**{.cve-chip} **No Patch at Disclosure**{.cve-chip}

    Multiple Tenda firmware versions contain a hidden authentication routine in `/bin/httpd` that accepts a hardcoded secret password and creates an admin session without verifying configured credentials. Attackers can gain full router control for DNS hijacking, traffic interception, and internal network pivoting.

    [Read more](2026/Week27/Tenda.md)

</div>