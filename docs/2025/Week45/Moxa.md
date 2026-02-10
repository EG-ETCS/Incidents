# Multiple Critical Vulnerabilities in Moxa ICS Network Appliances and Routers
![Moxa](images/Moxa.png)

**Multiple critical/high severity issues**{.cve-chip}
**Administrative takeover, lateral movement potential**{.cve-chip}

## Description

Five high-severity vulnerabilities (CVE-2025-6892 → CVE-2025-6950) were found in Moxa’s industrial routers, gateways, and security appliances running firmware versions prior to v3.21. Exploitation enables attackers to bypass authentication, escalate privileges, forge credentials, and remotely create administrator accounts. These flaws collectively expose affected devices to complete administrative takeover and potential lateral movement within OT networks.

## Technical Details

- **CVE-2025-6892 (Improper Authentication, CVSS 8.7):** Weak validation in REST API allows access to admin endpoints after any user login.
- **CVE-2025-6893 (Privilege Escalation, CVSS 9.3):** Low-privileged users can modify configurations and system parameters via improperly protected functions.
- **CVE-2025-6949 (Improper Authorization, CVSS 9.3):** Authenticated users can create or duplicate administrator accounts using API calls.
- **CVE-2025-6950 (Hard-coded JWT Secret, CVSS 9.9):** Static JSON Web Token secret embedded in firmware enables attackers to forge valid tokens and gain full admin access without credentials.

**Affected Products**

- Moxa EDR-G902, EDR-G903, EDR-G903-T (firewall/VPN routers)
- EDR-810 series industrial secure routers
- TN-5916, TN-5912, IKS-6728A managed switches
- Other models running firmware ≤ v3.20 (see MPSA-258121 for full list)

## Attack Scenario

- An attacker connects to the device’s exposed web or REST API interface.
- Using either low-privileged credentials, default accounts, or the hard-coded JWT key, the attacker authenticates.
- They exploit the API logic flaws to escalate privileges, add new admin users, or execute system commands.
- From the compromised router, the attacker can perform reconnaissance of the ICS network, alter routing/firewall rules, pivot laterally into PLCs or SCADA servers, or disrupt industrial processes.

## Impact

- Full administrative compromise of affected devices.
- Loss of confidentiality: exposure of VPN credentials, routing configs, and network topology.
- Loss of integrity & availability: attackers can change rules, disable interfaces, or redirect industrial traffic.
- Pivot potential: compromised devices serve as gateways into operational technology (OT) networks, enabling broader infrastructure attacks.

## Mitigations

- Upgrade firmware to v3.21 or later immediately (available on Moxa’s official portal).
- Restrict access to management interfaces (HTTP/HTTPS/API) via network segmentation, firewalls, or VPN whitelisting.
- Monitor logs for abnormal API calls, configuration changes, or new account creation.
- Disable unused diagnostic features (ping, traceroute) and rotate all administrative credentials post-update.

## Resources

1. [Multiple Vulnerabilities in Network Security Appliances and Routers](https://www.moxa.com/en/support/product-support/security-advisory/mpsa-258121-cve-2025-6892,-cve-2025-6893,-cve-2025-6894,-cve-2025-6949,-cve-2025-6950-multiple-vulnerabilities-in-netwo)
2. [Multiple Critical Vulnerabilities in Moxa Inc. ICS Network Appliances and Routers - CCB Safeonweb](https://ccb.belgium.be/advisories/warning-multiple-critical-vulnerabilities-moxa-inc-ics-network-appliances-and-routers)
3. [NVD - CVE-2025-6893](https://nvd.nist.gov/vuln/detail/CVE-2025-6893)
