# FCC Softens Foreign Router Ban and Allows Security Updates Until 2029
![alt text](images/Foreign.png)

**FCC Policy**{.cve-chip} **Router Security**{.cve-chip} **Supply Chain Risk**{.cve-chip} **Network Infrastructure**{.cve-chip}

## Overview

The Federal Communications Commission revised its earlier restrictive policy on foreign-manufactured routers. While restrictions on the procurement of new foreign-made networking devices remain in place, the FCC now permits existing devices to continue receiving firmware updates, security patches, bug fixes, and compatibility updates until 2029. The revision addresses a significant cybersecurity risk identified in the original proposal: blocking firmware signing services and patch distribution would have left millions of deployed routers permanently unpatched and exposed to exploitation.

## Technical Specifications

| Attribute | Details |
|---|---|
| **Regulatory Body** | Federal Communications Commission (FCC) |
| **Policy Change** | Foreign router ban revised to permit continued firmware/security updates for existing devices |
| **Update Permission Period** | Until 2029 |
| **Devices Affected** | Foreign-manufactured consumer and business routers already deployed |
| **New Purchases** | Restrictions on new foreign-made networking devices remain in place |
| **Security Risk Addressed** | Blocking firmware signing/patch distribution would leave deployed routers permanently unpatched |
| **CVE** | None — regulatory and supply-chain security policy |

## Affected Products

- **Foreign-manufactured routers** currently deployed in homes, businesses, and ISP infrastructure (notably devices from vendors subject to FCC covered-list restrictions, including certain TP-Link, Huawei, and ZTE products)
- **Any network** relying on firmware updates from vendors whose signing and distribution services could have been disrupted under the original policy

## Attack Scenario

The risk the FCC revision is designed to prevent:

1. A deployed router is blocked from receiving further firmware and security updates due to restrictions on vendor patch-signing services
2. Unpatched known vulnerabilities — including publicly documented CVEs — remain permanently exploitable on millions of devices
3. Attackers scan for routers running vulnerable firmware versions and exploit remote code execution or authentication bypass flaws
4. Threat actors gain router-level access, enabling traffic interception, credential harvesting, and persistence at the network perimeter
5. Compromised routers are enlisted into botnets (consistent with established campaigns against SOHO routers) or used for lateral movement into connected networks
6. Home users, businesses, and ISPs face sustained exposure with no remediation path if patch distribution is cut off

## Impact

=== "Security Risk of Blocking Updates"

    - Permanently unpatched routers become easy targets for known CVE exploitation and botnet recruitment
    - Millions of deployed devices across home users, businesses, and ISPs could be left vulnerable with no vendor-provided remediation path
    - Increased botnet activity, traffic interception, and network compromise at scale

=== "Policy and Supply Chain Implications"

    - The original policy risked creating a large population of permanently vulnerable end-of-life devices overnight, worsening the overall security posture of U.S. network infrastructure
    - The revised policy reflects a balance between national security concerns about foreign-made hardware and the practical reality that abrupt patch termination increases rather than reduces risk
    - Restrictions on new device procurement remain, maintaining supply-chain security goals for future infrastructure

=== "Residual and Long-Term Risk"

    - The 2029 deadline defers rather than resolves the underlying tension: when the exemption expires, the same unpatched-device risk will recur unless replacement programs are in place
    - National security concerns about foreign-manufactured routers in critical network paths remain unresolved by this revision; the policy addresses maintenance continuity, not hardware trustworthiness

## Mitigations

### Immediate Actions

- **Apply all available firmware updates immediately** on foreign-manufactured routers while patch distribution remains permitted; do not defer updates
- **Replace end-of-life or unsupported routers** — use the 2029 window as a planning horizon to migrate to devices from vendors with long-term, transparent security support commitments
- **Disable remote administration features** on routers where they are not actively needed to reduce the attack surface available via known vulnerabilities

### Hardening

- **Use strong, unique administrator passwords** on all routers and networking equipment; change defaults immediately on deployment
- **Segment IoT devices and untrusted equipment from critical systems** using VLANs or separate network zones to limit the impact of a compromised router
- **Monitor router logs and outbound traffic** for anomalous behavior indicative of exploitation or botnet activity

### Procurement and Planning

- **Purchase future devices from vendors with transparent security practices**, published vulnerability disclosure policies, and long-term firmware support commitments
- **Plan router replacement cycles** ahead of the 2029 exemption expiry for any foreign-manufactured devices currently in scope to avoid a repeat of the unpatched-device risk scenario

## :material-book-open-variant: Resources

!!! info "Open-Source Reporting"
    - [FCC Softens Ban on Foreign-Made Routers — SecurityWeek](https://www.darkreading.com/endpoint-security/fcc-softens-foreign-router-ban)
    - [FCC Updates Covered List to Include Foreign-Made Consumer Routers — Hackread](https://docs.fcc.gov/public/attachments/DOC-420034A1.pdf)

---

*Last Updated: May 12, 2026*