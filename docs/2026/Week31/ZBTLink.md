# Endlessdoors Backdoor in ZBTLink Routers
![alt text](images/ZBTLink.png)

**Router Supply-Chain Risk**{.cve-chip} **Hidden Firmware Function**{.cve-chip} **Remote Access Exposure**{.cve-chip} **Potential RCE Path**{.cve-chip} **Network Gateway Compromise**{.cve-chip}

## Overview

VulnCheck researchers reported an undocumented firmware component, named Endlessdoors, in more than 20 ZBTLink router models (also sold as Wiflyer).

The functionality appears in factory firmware before deployment and periodically contacts external infrastructure, raising concern that compromised or abused control channels could enable unauthorized administrative access and network-level compromise.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Issue Name** | Endlessdoors |
| **Affected Vendor/Branding** | ZBTLink / Wiflyer |
| **Model Scope** | 20+ router models |
| **Core Behavior** | Hidden firmware mechanism with recurring outbound communication |
| **Beacon Pattern** | Periodic callbacks (about every 35 seconds) to predefined IP/domain infrastructure |
| **Potential Security Effect** | Remote command delivery pathway with possible administrative control abuse |
| **Estimated Global Exposure** | 100,000+ deployed routers (reported estimate) |
| **Exploitation Status at Disclosure** | No publicly confirmed active exploitation |
| **Vendor Position** | Feature described as remote maintenance capability; firmware review announced |

## Affected Products

- ZBTLink router models carrying affected factory firmware
- Wiflyer-branded devices sharing the same firmware lineage
- Organizations using affected devices as internet edge/gateway infrastructure
- Environments where router trust is foundational for DNS, routing, and access-control policy

## Attack Scenario

1. Organization deploys vulnerable ZBTLink/Wiflyer router firmware.
2. Device initiates periodic outbound communications to predefined external infrastructure.
3. If that infrastructure or associated trust path is compromised/abused, attacker can push commands.
4. Administrative control over the router is gained.
5. Compromised gateway is used for traffic monitoring, DNS manipulation, credential theft, persistence, and pivoting into internal networks.

## Impact Assessment

=== "Integrity"

    - Unauthorized router-level control can alter routing, firewall, and DNS policies
    - Gateway compromise can subvert trust for all downstream client traffic
    - Attackers can establish durable control over network edge infrastructure

=== "Confidentiality"

    - Intercepted traffic and altered DNS can expose credentials and sensitive communications
    - Router compromise can provide visibility into internal network behavior and assets
    - Supply-chain placement in baseline firmware increases stealth and pre-deployment risk

=== "Availability"

    - Misconfiguration or malicious command execution can degrade or disrupt network connectivity
    - Compromised devices may be conscripted into botnet/distributed attacks, impacting stability
    - Recovery may require firmware replacement, hard resets, and credential/policy rebuilds

## Mitigation Strategies

### Asset Identification and Vendor Tracking

- Identify and inventory all ZBTLink/Wiflyer devices in production and staging.
- Monitor vendor advisories and apply verified firmware updates as soon as trusted releases are available.

### Exposure and Access Reduction

- Restrict or disable remote management functions where not operationally required.
- Limit administrative interfaces to trusted networks/VPN paths and hardened management endpoints.

### Traffic and Configuration Monitoring

- Monitor router outbound traffic for unexplained beaconing to unknown domains/IPs.
- Continuously review DNS, routing, and admin configuration changes for unauthorized modifications.

### Containment and Replacement Planning

- Segment critical systems to reduce blast radius from edge-device compromise.
- If trusted remediation firmware is unavailable, replace affected hardware with validated alternatives.
- Maintain continuous log monitoring and IoC-driven hunting for signs of compromise.

## Resources and References

!!! info "Public Reporting"
    - [Chinese-Made Zbtlink Routers Ship With Backdoor That Opens Unauthenticated Root Shells](https://thehackernews.com/2026/08/chinese-made-zbtlink-routers-ship-with.html)
    - [Chinese-made Zbtlink routers have backdoor, researchers say | Reuters](https://www.reuters.com/world/asia-pacific/chinese-made-zbtlink-routers-have-backdoor-researchers-say-2026-08-05/)
    - [Chinese-made Zbtlink routers have a backdoor, researchers say | Cybernews](https://cybernews.com/news/chinese-router-backdoor-zbtlink-security-risk/)
    - [Researchers report backdoor in Zbtlink routers affecting thousands of devices](https://cadeproject.org/updates/researchers-report-backdoor-in-zbtlink-routers-affecting-thousands-of-devices/)
    - [Chinese router vendor denies backdoor claims but pauses downloads for security fixes](https://www.theregister.com/security/2026/08/06/chinese-router-vendor-denies-its-firmware-contains-backdoors-but-pauses-downloads-to-fix-security-issues-anyway/5283794)

---

*Last Updated: August 6, 2026*
