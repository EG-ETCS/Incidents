# Unauthorized Access to Dahua Surveillance Cameras and Video Recorders via Easy4IP
![alt text](images/Dahua.png)

**Dahua**{.cve-chip} **Easy4IP P2P**{.cve-chip} **CVE-2021-33044**{.cve-chip} **CVE-2021-33045**{.cve-chip} **Surveillance Access**{.cve-chip}

## Overview

Ukraine's Computer Emergency Response Team (CERT-UA) reported unauthorized access to Dahua IP cameras and video recorders.

Attackers reportedly used the Easy4IP P2P/cloud remote-access feature to locate and access devices, including systems behind routers and firewalls. Reported activities included viewing live video, modifying device configurations, and creating unauthorized accounts.

The number of devices affected by the specific CERT-UA investigation and attacker identities were not disclosed.

## Technical Details

- Easy4IP P2P: Enables remote access through Dahua cloud infrastructure.
- Predictable serial numbers: May allow attackers to enumerate devices registered with the cloud service.
- CVE-2021-33044: Authentication-bypass vulnerability affecting certain Dahua products.
- CVE-2021-33045: A separate authentication-bypass vulnerability affecting certain Dahua products.
- Weak credentials: Default or easily guessed passwords may provide another route to unauthorized access.
- Indicators of compromise: Unknown user accounts, unauthorized configuration changes, and suspicious DVRIP authentication events originating from 127.0.0.1.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Incident Type** | Unauthorized access to surveillance infrastructure |
| **Primary Platform** | Dahua IP cameras and video recorders |
| **Remote Access Path** | Easy4IP P2P/cloud relay |
| **Vulnerability References** | CVE-2021-33044, CVE-2021-33045 |
| **Alternative Access Path** | Weak/default credentials |
| **Noted IoCs** | Unknown accounts, unauthorized config changes, DVRIP auth from 127.0.0.1 |
| **Disclosure Gaps** | Device count and attacker attribution not publicly disclosed |

## Affected Products

- Dahua IP cameras and network video recorders registered with Easy4IP.
- Devices running vulnerable firmware versions associated with CVE-2021-33044 and CVE-2021-33045.
- Deployments using weak or default credentials.

## Attack Scenario

1. The attacker enumerates predictable serial numbers to identify Dahua devices registered with Easy4IP.
2. The attacker uses cloud relay access to reach target devices without requiring directly exposed inbound ports.
3. The attacker attempts weak credentials or exploits authentication-bypass vulnerabilities in vulnerable firmware.
4. After gaining access, the attacker views video streams, changes settings, and creates unauthorized accounts to maintain access.

## Impact Assessment

=== "Security and Privacy Impact"

    - Unauthorized access to live surveillance footage
    - Exposure of sensitive information about people, facilities, and operations

=== "Operational Impact"

    - Unauthorized modification of camera and recorder configurations
    - Potential persistence via unauthorized account creation

=== "Business and Critical-Infrastructure Risk"

    - Increased security risks for government facilities, businesses, and critical infrastructure using affected devices

## Mitigation Strategies

1. Disable Easy4IP/P2P functionality when cloud remote access is unnecessary.
2. Update affected devices to the latest supported firmware addressing relevant vulnerabilities.
3. Replace default or weak passwords with strong, unique credentials.
4. Review device accounts and remove unauthorized users and cloud associations.
5. Inspect audit logs and investigate unexpected configuration changes.
6. Isolate surveillance systems on dedicated network segments and restrict unnecessary communications.
7. Use a VPN and restrict remote access to authorized users and networks.
8. Inventory all Dahua cameras and recorders, including potentially overlooked devices.

## Resources and References

!!! info "Public Reporting"
    1. [Attackers Take Control of Dahua Cameras and Video Recorders Via Easy4IP](https://securityaffairs.com/201827/hacking/attackers-take-control-of-dahua-cameras-and-video-recorders-via-easy4ip.html)
    2. [Attackers Hijack Dahua IP Cameras in Ukraine Using P2P Access and Auth Weaknesses](https://thehackernews.com/2026/10/attackers-hijack-dahua-ip-cameras-in.html)
    3. [Ukraine warns hackers are exploiting Chinese-made Dahua surveillance cameras | The Record](https://therecord.media/ukraine-cert-ua-warning-chinese-dahua-cameras-hacked)
    4. [DHCC-SA-202106-001 Security Advisory - Identity authentication bypass vulnerability found in some Dahua products](https://www.dahuasecurity.com/about-dahua/trust-center/dahua-psirt/dhcc-sa-202106-001%3Asecurity-advisory---identity-authentication-bypass-vulnerability-found-in-some-dahua-products)

---

*Last Updated: October 29, 2026*
