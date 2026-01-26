# Everest Ransomware Leaks AT&T and Aviation Records

**Data Breach**{.cve-chip}
**Ransomware Group**{.cve-chip}
**2.1M+ Records**{.cve-chip}
**Identity Theft Risk**{.cve-chip}


## Description

Between October 21–28, 2025, the Everest ransomware group leaked sensitive databases from three major organizations: AT&T Careers (US telecom), Dublin Airport (Ireland), and Air Arabia (UAE airline), and offered the stolen datasets for sale via dark web extortion posts. This campaign primarily involved unverified data exfiltration and extortion rather than confirmed ransomware encryption but involved high-profile targets and personal information at risk.

## Technical Details

### Attack Method
- **Primary Method**: Data theft and extortion, no technical evidence of system encryption yet
- **Attack Vectors**: Credentials/recruitment platform compromise suspected
- **AT&T Compromise**: Jobs portal reportedly compromised
- **Aviation Targets**: Leaks appear to center around backend operational databases

### Evasion Techniques
Everest often relies on:
- **Credential theft**
- **Remote desktop compromise** 
- **Third-party supplier weakness** (according to NCC Group and Cybernews)

### Nature of Exfiltrated Data

#### AT&T Careers
- **576,000 records** including:
  - Names, phone numbers, emails
  - Possibly resumes/applicant data

#### Dublin Airport  
- **1.5M passenger records** including:
  - Names, IDs, flight details, seat numbers
  - Frequent flyer status, travel class
  - Device info, baggage data
  - Security/boarding flags

#### Air Arabia
- **18,000 employee records** including:
  - Employment status, HR and manager data
  - Contact info, login methods
  - Desk location, address, review dates
  - Assignment codes

## Attack Scenario

### Data Exposure Timeline
- Data leaks posted on Everest's dark web site after ransom deadlines passed
- Threats to expose further details if negotiations fail

### Dark Web Sales
- **AT&T**: No posted price (already leaked)
- **Dublin Airport**: $1M asking price
- **Air Arabia**: $2M asking price

### Secondary Risks
- No confirmation from victim organizations on authenticity or direct system compromise
- Airline passenger and employee data can be used for:
  - Identity theft
  - Phishing campaigns
  - Insider fraud
  - Supply-chain risks

## Impact

### Identity & Privacy Risk
- Exposed traveler and staff data enables targeted attacks
- HR/HRMS compromise potential
- Tailored phishing, fraud, or impersonation schemes at scale

### Operational Risk
- **Airports and Airlines**: Leaks may reveal travelers' movements and airline processes
- Internal operational details suitable for further attacks

### Corporate Reputation
- **AT&T and Air Arabia**: HR, recruitment, and staff account-based impersonation risks

### Critical Exposure
- **Aviation security**
- **Telecom infrastructure** 
- **Public infrastructure**
- **Supply-chain security**
- Risk of secondary/follow-on attacks given sensitivity and granularity of leaked information

## Mitigations

### Immediate Incident Response
- All affected organizations should publicly engage
- Offer password resets and inform affected users
- Initiate forensic investigations and monitoring for misuse

### Credential Security
- **Urgent**: Rotate passwords/user IDs
- Increase MFA and access controls
- Monitor for credential leaks

### Legal/Communications
- Coordinate with CERT and law enforcement for breach reporting
- Takedown of dark web sale posts

### Supplier Chain Review
- Audit partners for remote access
- Segment backend platforms for HR, travel, and recruitment data

### Customer Defense
- Implement fraud monitoring
- Exercise caution around unsolicited requests and suspicious login prompts

## Resources

1. [Everest Ransomware Attack on AT&T Careers](https://www.dexpose.io/everest-ransomware-attack-on-att-careers/)
2. [Everest AT&T Leak Dublin Airport Data](https://hackread.com/everest-att-leak-dublin-airport-data/)

---
