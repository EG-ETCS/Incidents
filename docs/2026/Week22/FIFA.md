# FIFA World Cup 2026 Fraud and Phishing Campaign
![alt text](images/FIFA.png)

**Phishing**{.cve-chip} **Typosquatting**{.cve-chip} **Financial Fraud**{.cve-chip} **Event-Themed Scam**{.cve-chip}

## Overview

The FBI issued a warning about widespread fraudulent websites impersonating FIFA and FIFA World Cup 2026 services. Cybercriminals are exploiting the event's global popularity to deploy convincing fake websites offering tickets, hospitality packages, merchandise, streaming services, betting opportunities, and employment. A large-scale operation identified by Group-IB, dubbed **"Ghost Stadium"**, uses cloned FIFA portals, fake Single Sign-On (SSO) pages, multilingual phishing sites, malicious advertisements, and search-engine manipulation to funnel victims to fraudulent pages. The objective is to steal money, payment card information, credentials, and personal data.

## Technical Specifications

| Attribute | Details |
|---|---|
| **Campaign Name** | Ghost Stadium (Group-IB); broader FIFA World Cup 2026 phishing ecosystem |
| **Threat Actor Type** | Cybercriminal (financially motivated); multiple independent actors |
| **Primary Technique** | Typosquatting, lookalike domains, cloned FIFA portals |
| **Infrastructure** | Thousands of FIFA-themed malicious domains; fake SSO pages; multilingual phishing sites |
| **Delivery Vectors** | Malicious search ads, SEO poisoning, social media, direct links |
| **Targets** | Football fans, ticket seekers, event attendees, job seekers, gamblers |
| **Data Stolen** | Payment card data, credentials, PII (name, email, phone, address) |

## Affected Services

- **FIFA official ticketing and services** — impersonated by lookalike domains targeting fans purchasing tickets and hospitality packages
- **Users searching for** World Cup tickets, streaming, merchandise, accommodation, betting, and employment related to the 2026 tournament
- **Organizations** whose employees may reuse credentials compromised on fraudulent FIFA-themed pages

## Attack Scenario

1. A victim searches online for FIFA World Cup 2026 tickets, streaming options, merchandise, or employment opportunities
2. A malicious sponsored advertisement or manipulated search result directs the victim to a fraudulent FIFA-themed website — registered via typosquatting (e.g., `fifa-tickets2026[.]com`) or alternative TLDs to appear credible
3. The cloned portal closely mimics legitimate FIFA services, sometimes offering multiple languages and fake SSO login flows to increase believability
4. The victim enters account credentials, personal information, and payment card details to complete a purchase, register, or apply
5. Attackers collect submitted data in real time; victims either receive nothing or a convincing confirmation page while their payment is fraudulently processed
6. Stolen credentials and card data are used for account takeover, unauthorized charges, identity theft, or sold on underground marketplaces; organizations with employees who reuse credentials face secondary risk

## Impact

=== "Financial and Personal Impact"

    - Direct financial losses from fraudulent ticket, merchandise, and hospitality purchases
    - Payment card theft enabling unauthorized charges beyond the initial transaction
    - Identity theft using stolen PII (name, address, email, phone) for follow-on fraud and social-engineering attacks

=== "Credential and Account Risk"

    - Credential compromise enabling account takeover on FIFA and related platforms
    - Password reuse risk — compromised credentials may be replayed against corporate email, VPN, or SaaS services used by affected individuals
    - Phishing kits capturing credentials in real time allow immediate account takeover before victims notice anything is wrong

=== "Organizational and Reputational Risk"

    - Organizations with employees who submit credentials to fake FIFA pages face credential-reuse risk across enterprise systems
    - Reputational damage to FIFA and legitimate authorized vendors from a wave of consumer fraud conducted in their name
    - Increased volume of phishing complaints and law-enforcement engagement during the tournament period complicates response

## Mitigations

### For Individuals and Fans

- **Access FIFA services only through official websites** — use `fifa.com` and the official FIFA+ app; navigate directly rather than via search ads or social media links
- **Bookmark trusted FIFA and authorized ticketing websites** before you need them; avoid searching for tickets or hospitality during high-demand periods when fraudulent ads surge
- **Verify domain names carefully** before entering credentials or payment information — check for subtle misspellings, extra hyphens, or unusual TLDs (`.net`, `.org`, `.shop` instead of `.com`)
- **Avoid clicking sponsored search advertisements** for World Cup ticket sales; paid placements can be purchased by fraudsters and ranked above legitimate results
- **Use multi-factor authentication (MFA)** on all accounts associated with ticketing, travel, and email to limit damage from credential compromise
- **Monitor financial accounts** for suspicious transactions following any FIFA-related purchase; report fraudulent charges promptly to your card issuer

### For Organizations

- **Train employees to recognize typosquatting and phishing attempts** — awareness is the primary control; brief staff specifically on event-themed phishing spikes tied to major sporting events
- **Implement email and web filtering** to block known phishing domains and FIFA-themed typosquats flagged by threat intelligence feeds
- **Monitor for credential reuse risk** — if employees report falling victim to phishing, treat it as a potential enterprise credential compromise and initiate password rotation for corporate accounts

## Resources

!!! info "Open-Source Reporting"
    - [FBI Warns of Fake FIFA Websites Running World Cup Fraud Schemes](https://www.bleepingcomputer.com/news/security/fbi-warns-of-fake-fifa-websites-running-world-cup-fraud-schemes/)
    - [Threat Actors Spoofing FIFA Websites in Advance of the 2026 World Cup — FBI IC3](https://www.ic3.gov/PSA/2026/PSA260527)
    - [FBI Warns of Fake FIFA Websites Targeting Houston Fans Ahead of 2026 World Cup](https://gmg-kprc-prod.cdn.arcpublishing.com/news/local/2026/05/28/ever-heard-of-typo-squatting-fbi-warns-of-fake-fifa-websites-targeting-fans-ahead-of-2026-world-cup/)
    - [The Ghost Stadium Score: Billions At Stake At The World's Largest Football Tournament — Group-IB Blog](https://www.group-ib.com/blog/ghost-stadium-football-fraud/)

---

*Last Updated: June 1, 2026*