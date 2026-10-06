# Mabna Institute Cyber-Theft Campaign
![alt text](images/Mabna.png)

**Mabna Institute**{.cve-chip} **Academic Cyber-Theft**{.cve-chip} **Credential Theft**{.cve-chip} **Data Exfiltration**{.cve-chip} **Spear-Phishing**{.cve-chip}

## Overview

U.S. prosecutors allege that members of the Iran-based Mabna Institute conducted a years-long cyber campaign to steal academic research, intellectual property, credentials, and email data.

Public reporting states the operation allegedly stole more than 31 TB of data and compromised approximately 8,000 professor email accounts

## Technical Details

- Initial access reportedly relied on targeted spear-phishing and social engineering.
- Additional methods reportedly included credential theft/reuse, password attacks, and reconnaissance.
- Compromised university accounts were used to access library systems and research resources.
- Stolen credentials enabled lateral access expansion across academic environments.
- Data was allegedly exfiltrated to attacker-controlled infrastructure outside the United States.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Campaign Type** | Long-term cyber-enabled academic theft and espionage-style collection |
| **Alleged Actor Context** | Mabna Institute members, per U.S. prosecutorial reporting |
| **Primary Techniques** | Spear-phishing, credential attacks, reconnaissance, account compromise |
| **Primary Targets** | Professors, researchers, university email systems, and library/research resources |
| **Data Objective** | Academic research, intellectual property, credentials, and email content |
| **Exfiltration Pattern** | Transfer to attacker-controlled infrastructure outside U.S. jurisdiction |

## Affected Products

- University email platforms and identity systems.
- Academic library access portals and subscription resources.
- Research repositories containing intellectual property and unpublished academic work.

## Attack Scenario

1. Identify professors/researchers and map subject-matter interests.
2. Conduct reconnaissance on institutions, users, and account workflows.
3. Deliver convincing spear-phishing messages.
4. Capture credentials and/or reuse previously stolen credentials.
5. Access university email and library systems.
6. Maintain access and harvest additional credentials.
7. Collect academic research and intellectual property.
8. Exfiltrate data to attacker-controlled infrastructure.
9. Provide or sell stolen information to interested Iranian entities and universities (per reporting allegations).

## Impact Assessment

=== "Primary Impact"

    - More than 31 TB of academic data and intellectual property allegedly stolen
    - Approximately 8,000 professor accounts reportedly compromised
    - Hundreds of universities and organizations reportedly targeted

=== "Financial and Operational Impact"

    - U.S. authorities cited estimated losses/damages exceeding $3.4 billion in related reporting
    - Universities incurred substantial forensic, legal, and remediation costs
    - Long-term exposure risk for sensitive academic and research programs

=== "Strategic Impact"

    - Potential long-term erosion of research advantage through sustained theft of academic IP and communications

## Mitigation Strategies

1. Enforce phishing-resistant MFA (FIDO2/WebAuthn) for faculty, researchers, and administrators.
2. Implement strong email security and anti-phishing controls.
3. Monitor suspicious authentication behavior, including impossible-travel events.
4. Disable legacy authentication paths where feasible.
5. Apply least privilege to research and library systems.
6. Segment sensitive research repositories from general user access paths.
7. Monitor for abnormal bulk downloads and data-exfiltration patterns.
8. Regularly review exposure from compromised/stolen credential datasets.
9. Conduct phishing-awareness training tailored to researchers and faculty.
10. Maintain centralized logging and long-term threat-hunting workflows.

## Resources and References

!!! info "Public Reporting"
    - [Iranian hacker accused of draining 31TB from university inboxes extradited to the US](https://securityaffairs.com/200387/security/iranian-hacker-accused-of-draining-31tb-from-university-inboxes-extradited-to-the-us.html)
    - [Iranian extradited to US by Montenegro over cyberattacks | AP News](https://apnews.com/article/montenegro-iranian-hacker-extradited-us-fa06e3712d1f3a2835c913d1c945ae24)
    - [In Rare Move, Alleged Iranian State Hacker Extradited to US - SecurityWeek](https://www.securityweek.com/in-rare-move-iranian-hacker-accused-of-working-for-irgc-extradited-to-us/)
    - [Office of Public Affairs | 17 Iranians Charged with Conducting Massive Cyber Theft Campaign on Behalf of the Islamic Revolutionary Guard Corps and Other Iranian Entities | United States Department of Justice](https://www.justice.gov/opa/pr/17-iranians-charged-conducting-massive-cyber-theft-campaign-behalf-islamic-revolutionary)
    - [Iranian accused of hacking American universities extradited from Montenegro | The Record from Recorded Future News](https://therecord.media/iran-montenegro-hacker-extradition)

---

*Last Updated: October 6, 2026*
