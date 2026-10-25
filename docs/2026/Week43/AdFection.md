# AdFection Advertising-Based Delivery of Candiru Spyware
![alt text](images/AdFection.png)

**AdFection**{.cve-chip} **Candiru Spyware**{.cve-chip} **Zero-Click Delivery**{.cve-chip} **Ad Ecosystem Abuse**{.cve-chip} **Targeted Surveillance**{.cve-chip}

## Overview

Citizen Lab uncovered an operation named AdFection that abuses targeted online advertisements to profile users and deliver Candiru spyware without requiring victims to click an advertisement.

The research links this mechanism to Discover-Tech, an Israeli advertising company whose Controlium platform bridges online advertising infrastructure and commercial surveillance operations.

Between 2024 and 2025, at least 45 devices within Al Jazeera were targeted in AdFection attacks leading to Candiru spyware. SecurityWeek reports confirmed infections but does not provide a separate count of successfully infected devices. The 45-device figure should therefore be treated as a targeting count, not a verified infection total.

This is a surveillance-campaign and advertising-ecosystem abuse investigation, not a single breach of an advertising platform. SecurityWeek published its coverage on October 17, 2026.

## Technical Details

### Advertising-based delivery mechanism

The operation exploits the online advertising ecosystem, where companies participate in real-time bidding (RTB) auctions to display advertisements to selected users. Advertising exchanges collect device and user information, while advertisements can execute code within a browser or application for tasks such as impression and click tracking.

Citizen Lab found that many Discover-Tech advertisements contain a script that automatically contacts company infrastructure, submits a user advertising identifier, and executes JavaScript returned according to a combination of IP addresses and identifiers. This enables selective profiling and delivery of different code to different users.

### Controlium and zero-click targeting

Discover-Tech's Controlium platform supports user de-anonymization, device fingerprinting, and zero-click compromise when an advertisement is displayed on a target device. No advertisement click is required for the reported delivery mechanism.

Citizen Lab confirmed that the platform was used to profile users and infect devices on behalf of Candiru, an Israel-based commercial spyware vendor. The supplied article does not disclose the complete exploit chain, associated CVEs, affected operating-system versions, or exact browser/application vulnerabilities.

### Scale and exposure

Citizen Lab identified an exposed Discover-Tech server containing four billion advertising bid records. The records showed Discover-Tech advertisements appearing across nearly 200,000 unique websites and Android and iOS applications worldwide.

These figures describe advertising records and distribution reach. They do not establish that four billion users, or users of all 200,000 websites and applications, were infected or individually selected for spyware deployment.

### Related de-anonymization activity

Citizen Lab also examined Discover-Tech interactions with other surveillance actors. One, tracked as Dark Cartographer, reportedly builds databases linking mobile advertising identifiers to telephone numbers by exploiting vulnerabilities across mobile carriers.

This is a related surveillance activity described in the research. The article does not establish that Dark Cartographer conducted every AdFection attack or that carrier exploitation was a required stage in each Candiru infection.

### Attribution and exploitation status

Citizen Lab links the advertising infrastructure to Discover-Tech and confirms its use on behalf of Candiru. Discover-Tech is assessed as likely serving as a front for a broader spyware and espionage operation, potentially involving multiple commercial-surveillance partners.

The article does not identify the government customer, operator, or country that commissioned targeting of Al Jazeera. The vendors' location does not establish end-customer identity.

Spyware infections are reported as confirmed, but the article does not establish whether the same infrastructure remained operational after advertising-industry restrictions were imposed in early October 2026.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Campaign Name** | AdFection |
| **Spyware Family** | Candiru commercial spyware |
| **Delivery Vector** | Advertising-ecosystem script execution and selective JavaScript delivery |
| **User Interaction Requirement** | Reported zero-click path during ad rendering |
| **Key Infrastructure** | Discover-Tech advertising stack and Controlium platform |
| **Targeting Scope Mentioned** | At least 45 Al Jazeera devices targeted (2024-2025) |
| **Exposure Data Point** | 4 billion ad-bid records on an exposed server |
| **Distribution Reach Indicator** | Ads observed across nearly 200,000 websites/apps |
| **CVE Disclosure Status** | Complete exploit chain and CVEs not publicly disclosed in supplied source |

## Affected Products

- Browser and in-app advertising surfaces where malicious ad-delivery scripts can execute.
- Devices receiving targeted ad content through participating ad exchanges and applications.
- High-risk users such as journalists and other surveillance-prone roles.

## Attack Scenario

1. Advertising identifiers, IP addresses, and other device data are used to recognize or select users for profiling.
2. Discover-Tech purchases advertising opportunities through online ad channels on sites/apps used by targets.
3. When an ad is displayed, embedded code contacts Discover-Tech infrastructure and submits advertising identifiers.
4. Infrastructure returns JavaScript based on identifiers and IP context, with selected targets receiving spyware-related delivery logic.
5. Reported zero-click compromise can occur without any ad click.
6. Compromised devices are used for surveillance, though source reporting does not enumerate all exfiltrated data per target.

## Impact Assessment

### Confirmed findings

- At least 45 Al Jazeera devices were targeted between 2024 and 2025; infections are reported, but successful-infection count is not separately provided.
- Discover-Tech infrastructure supported profiling, device fingerprinting, and Candiru delivery workflows.
- An exposed server contained four billion ad-bid records spanning nearly 200,000 websites and mobile applications.

### Potential impact

Linking advertising identifiers, IP addresses, and phone numbers can undermine anonymity and enable selective surveillance. For journalists and other high-risk individuals, device compromise may threaten confidential communications, professional contacts, and source protection.

These are potential consequences; the supplied report does not disclose specific stolen messages, exposed sources, or resulting physical harm.

Zero-click delivery also means avoiding suspicious links alone is insufficient, because delivery code may execute while viewing otherwise legitimate websites/apps.

### Sector and ecosystem impact

The affected ecosystem includes digital advertising, ad exchanges, mobile apps, browser-based services, and commercial surveillance platforms. The confirmed target organization named in the source is a news network, not a complete victim-sector list.

### Criticality

Assessment: High overall, and potentially severe for individually targeted users.

This reflects reported zero-click spyware infections, selective targeting of a news organization, and large-scale profiling capability. It does not imply all users exposed to Discover-Tech advertisements were infected.

## Mitigation Strategies

In early October 2026, reporting indicates:

- Google and IAB Europe removed Discover-Tech from advertising-vendor registries.
- Google blocked Discover-Tech access to its advertising exchanges.
- Beeswax and Eskimi reportedly took similar actions.

These measures reduce access via named channels, but do not confirm complete dismantlement of the operation.

### Recommended defensive actions

1. Block targeted advertising at the gateway, identified by Citizen Lab as the most feasible protection while ad ecosystems cannot reliably block all AdFection-style vectors.
2. Validate protective coverage across managed browsers, mobile apps, and remote-user contexts; browser-only controls may miss in-app paths.
3. Keep endpoints and applications updated; because the exploit chain is undisclosed, no single patch can be treated as complete remediation.
4. Investigate suspected targeted devices with specialist mobile/endpoint forensics and preserve evidence.
5. Scope identity and communications exposure, revoke sessions, and rotate relevant credentials from trusted devices when compromise is confirmed.
6. Update threat models for high-risk personnel to include advertising-based zero-click delivery that does not depend on clicking a malicious ad.

Items 2-6 are general defensive recommendations, not actions confirmed as implemented by all affected organizations.

## Resources and References

!!! info "Public Reporting"
    - [SecurityWeek - Israeli Ad Firm Doubled as Candiru's Zero-Click Spyware Delivery Channel (October 17, 2026)](https://www.securityweek.com/israeli-ad-firm-doubled-as-candirus-zero-click-spyware-delivery-channel/)

---

*Last Updated: October 25, 2026*
