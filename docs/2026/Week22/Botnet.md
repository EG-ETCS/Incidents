# Dutch Authorities Dismantle 17-Million-Device Botnet
![alt text](images/Botnet.png)

**Botnet Takedown**{.cve-chip} **Residential Proxy**{.cve-chip} **ASOCKS**{.cve-chip} **Law Enforcement**{.cve-chip}

## Overview

Dutch authorities dismantled one of the largest known botnets, consisting of approximately 17 million compromised devices spanning computers, smartphones, tablets, routers, and other internet-connected devices. The operation involved the seizure of more than 200 servers hosted in the Netherlands that were allegedly used to manage and support the botnet infrastructure. Investigators believe the seized infrastructure was connected to the **ASOCKS** residential proxy network — a criminal service enabling subscribers to route malicious traffic through victim devices to disguise their true origin. The investigation was initiated after a security researcher reported suspicious activity to the Dutch National Cyber Security Centre (NCSC).

## Technical Specifications

| Attribute | Details |
|---|---|
| **Operation Type** | Law enforcement botnet takedown and server seizure |
| **Botnet Scale** | ~17 million compromised devices |
| **Device Types** | Computers, smartphones, tablets, routers, IoT devices |
| **Servers Seized** | 200+ command-and-control and proxy-management servers |
| **Server Location** | Dutch data centers |
| **Associated Network** | ASOCKS residential proxy service |
| **Traffic Abuse** | Malicious traffic routed through victim devices to appear legitimate |
| **Investigation Origin** | Report by security researcher to Dutch NCSC |
| **Conducting Authority** | Dutch National Police / NCSC |

## Affected Products

- **Residential consumer devices** — home computers, smartphones, and tablets infected with botnet malware
- **Routers and IoT devices** — home and SME network equipment enrolled into the proxy network without owner knowledge
- **ASOCKS infrastructure** — residential proxy service and associated command-and-control servers hosted in the Netherlands

## Attack Scenario

1. Attackers compromise vulnerable consumer and enterprise devices through malware infections, exploitation of unpatched vulnerabilities, or weak/default security controls on routers and IoT equipment
2. Infected devices are silently enrolled into the botnet and registered with the ASOCKS residential proxy network, with no indication to the device owner
3. Cybercriminals purchase access to proxy sessions within the network, selecting exit nodes by country, city, or ISP to impersonate legitimate residential internet users
4. The rented proxy infrastructure is leveraged to conduct phishing campaigns, spam operations, DDoS attacks, web scraping, credential stuffing, fraud, and other cybercriminal activities — with all traffic appearing to originate from ordinary consumer devices rather than attacker-controlled hosts
5. The distributed nature of the network across 17 million devices in multiple countries makes automated blocking, traffic analysis, and law enforcement attribution significantly more complex
6. Dutch authorities — triggered by a security researcher report to the NCSC — identify and seize more than 200 servers in Dutch data centers used to manage the botnet and proxy service, dismantling a major criminal infrastructure component

## Impact

=== "Criminal Infrastructure Impact"

    - Removal of a major residential proxy network that enabled large-scale cybercrime while making malicious traffic appear to originate from legitimate consumer devices
    - Disruption of criminal operations relying on ASOCKS-routed traffic for phishing, spam, credential abuse, DDoS, and fraud — potentially affecting a wide ecosystem of cybercriminal customers
    - Seizure of 200+ servers representing significant operational infrastructure; may yield intelligence on users of the proxy service and downstream criminal operations

=== "Victim Device Impact"

    - Approximately 17 million device owners had their bandwidth, computing resources, and network reputation abused without their knowledge or consent
    - Residential proxy abuse can result in IP address blacklisting, degraded internet performance, and association of victim IP addresses with criminal activity — leading to service disruptions for legitimate users
    - Device owners typically have no indication their equipment is enrolled in a botnet unless proactive monitoring is in place

=== "Attribution and Systemic Challenges"

    - Residential proxy networks fundamentally complicate cyber-attack attribution by ensuring malicious traffic originates from legitimate consumer IP addresses rather than identifiable attacker infrastructure
    - The scale (17 million devices, 200+ servers) indicates long-running, industrialized operation — the disruption may temporarily reduce criminal capacity but does not eliminate the underlying market for residential proxy abuse services
    - Successor services or reconstructed infrastructure may emerge unless criminal operators are prosecuted

## Mitigations

### Device and Network Hardening

- **Apply security updates** to operating systems, routers, and IoT devices promptly; unpatched vulnerabilities and default credentials are primary vectors for botnet enrollment
- **Replace end-of-life equipment** that no longer receives vendor security updates — particularly consumer routers and IoT devices
- **Use strong, unique passwords** for all devices and accounts; enable multi-factor authentication (MFA) wherever supported
- **Restrict unnecessary remote management services** (e.g., Telnet, UPnP, remote administration panels) on routers and IoT equipment exposed to the internet

### Monitoring and Detection

- **Monitor network traffic** for unusual or high-volume outbound connections, particularly to unfamiliar IP ranges or at unusual hours — a common indicator of botnet activity
- **Install endpoint security solutions** capable of detecting malware and botnet agents on computers and mobile devices; ensure definitions are kept current
- **Regularly audit connected devices** within enterprise and home networks; unrecognized or unexpected devices may indicate unauthorized enrollment

### Operational Hygiene

- **Install software only from trusted, verified sources**; trojanized applications are a common botnet distribution vector
- **For enterprises**: implement network segmentation to limit the blast radius if a device is compromised; restrict lateral movement capabilities available to enrolled botnet agents

## Resources

!!! info "Open-Source Reporting"
    - [Dutch Authorities Dismantle Botnet Linked to 17 Million Infected Devices — The Hacker News](https://thehackernews.com/2026/05/dutch-authorities-dismantle-botnet.html)
    - [Botnet of 17 Million Devices Dismantled in the Netherlands](https://securityaffairs.com/192890/malware/botnet-of-17-million-devices-dismantled-in-the-netherlands.html)
    - [Dutch Govt Disrupts Malware Botnet with 17 Million Infected Devices — BleepingComputer](https://www.bleepingcomputer.com/news/security/dutch-govt-disrupts-malware-botnet-with-17-million-infected-devices/)
    - [Botnet of More Than 17 Million Devices Dismantled — Ars Technica](https://arstechnica.com/security/2026/05/botnet-of-more-than-17-million-devices-dismantled/)
    - [Dutch Police Disrupts Botnet Composed of 17 Million Devices — Help Net Security](https://www.helpnetsecurity.com/2026/05/29/dutch-police-disrupts-botnet-composed-of-17-million-devices/)

---

*Last Updated: June 1, 2026*