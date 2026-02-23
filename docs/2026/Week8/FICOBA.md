# FICOBA National Bank Account Database Breach (France)
![alt text](images/FICOBA.png)

**Data Breach**{.cve-chip}  **Credential Compromise**{.cve-chip}  **Financial Data**{.cve-chip}  **Government Database**{.cve-chip}

## Overview
A malicious actor used stolen login credentials from a government official to gain unauthorized access to the Fichier national des comptes bancaires et assimilés (FICOBA)—the central French national database recording all bank accounts. Approximately 1.2 million account records were accessed, including personal and financial identifiers such as RIB/IBAN numbers, full names, residential addresses, tax identification numbers, and potentially birth dates and places. While authorities confirmed no access to account balances or ability to conduct transactions, the exposure of banking identifiers creates significant risk for identity theft, fraud, and unauthorized direct debit schemes targeting affected individuals.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Incident Type** | Unauthorized database access via credential compromise |
| **Target System** | FICOBA (French National Bank Account Registry) |
| **Records Exposed** | Approximately 1.2 million account records |
| **Attack Vector** | Stolen government official credentials |
| **Initial Access Method** | Legitimate login credentials (compromised) |
| **Data Accessed** | RIB/IBAN, names, addresses, tax IDs, birth information |
| **Data NOT Accessed** | Account balances, transaction history, transaction capability |
| **Geographic Scope** | France (1.2M French account holders) |
| **Detection Status** | Identified through monitoring/audit |

## Affected Products
- FICOBA (Fichier national des comptes bancaires et assimilés) database
- French government official accounts and credentials
- Bank accounts and personal records of approximately 1.2 million French citizens
- Financial institutions whose customers' data was exposed
- Status: Breach concluded, investigation ongoing

## Technical Details

### Initial Access Method
- **Credential Type**: Legitimate government official login credentials
- **Compromise Method**: Not publicly detailed (likely phishing, password reuse, or credential theft)
- **Victim Profile**: Government official with database access privileges
- **Attack Surface**: FICOBA internal system access portal
- **Authentication**: Standard username/password (likely insufficient controls)

### Database Access Exploitation
- **Entry Point**: Internal system providing access to FICOBA
- **Query Method**: Attacker queried database for financial records
- **Record Count**: Approximately 1.2 million account records accessed
- **Detection**: Access eventually identified through monitoring or audit mechanisms
- **Duration**: Access remained undetected for some period before discovery

### Exposed Data Classification

**Personal Identifiers:**

- Full names of account holders
- Residential addresses
- Tax identification numbers

**Financial Identifiers:**

- RIB (Relevé d'Identité Bancaire) numbers
- IBAN (International Bank Account Number)
- Bank names and branch information
- Account holder relationships to financial institutions

**Data NOT Compromised:**

- Account balances
- Transaction history or records
- Ability to conduct transactions or transfers
- Digital banking credentials or passwords

### Access Control Failures
- Insufficient multi-factor authentication requirements
- Lack of role-based access controls (RBAC) limitations
- Inadequate monitoring of database query activity
- No real-time alerting for anomalous data access patterns
- Excessive privileges assigned to compromised credentials

## Attack Scenario
1. **Credential Compromise**:
    - Attacker obtains legitimate government official's login credentials
    - Method likely includes phishing, credential reuse, or password theft
    - Credentials provide legitimate access to FICOBA internal systems
    - No indication of exploit or vulnerability abuse

2. **Unauthorized Access**:
    - Attacker uses stolen credentials to log into FICOBA system
    - Authentication accepted with legitimate government credentials
    - Attacker gains access to internal database query interface
    - No additional authorization checks or MFA required

3. **Database Query & Data Extraction**:
    - Attacker performs broad queries against FICOBA database
    - Approximately 1.2 million account records queried and viewed
    - Personal and financial identifiers extracted
    - Data potentially exported or noted for later use

4. **Undetected Access Period**:
    - Unauthorized access continues unmonitored
    - Insufficient logging or alerting on database access
    - Attacker activity blends with legitimate official access patterns
    - Breach eventually identified through audit or monitoring

5. **Discovery & Investigation**:
    - Breach identified through periodic audits or access monitoring
    - Investigation confirms attacker accessed ~1.2 million records
    - Authorities determine no financial transactions conducted
    - French government launches public notification and support

## Impact Assessment

=== "Personal & Financial Privacy"
    * Exposure of personal identifiers (names, addresses, tax identification)
    * Disclosure of banking identifiers (IBAN/RIB) to attacker
    * Loss of privacy regarding bank account holders and relationships
    * Permanent record of exposed personal and financial data
    * Psychological impact on 1.2 million affected individuals

=== "Fraud & Financial Risk"
    * Increased vulnerability to phishing using personal information
    * SMS scams and social engineering with legitimate banking details
    * Unauthorized direct debit scheme setup using exposed IBANs
    * Risk of fraudulent mandate authorization using banking identifiers
    * Potential for transfer fraud using legitimate account identifiers

=== "Identity Theft Risk"
    * Exposed tax identification numbers facilitate identity fraud
    * Birth information combined with financial data enables comprehensive identity theft
    * Risk of fraudulent account opening using personal identifiers
    * Potential for targeted social engineering attacks

=== "Government & Institutional Impact"
    * Breach of national financial infrastructure and security
    * Loss of public confidence in government data security
    * Regulatory and compliance violations (GDPR potentially)
    * Operational impacts on FICOBA and dependent financial systems
    * Government accountability and reputational damage

## Mitigation Strategies

### For Affected Individuals
- **Account Monitoring**: Monitor bank accounts regularly for unusual direct debit or payment attempts
- **Fraud Alerts**: Place fraud alerts with major credit bureaus and financial institutions
- **Creditor Lists**: Use "trusted creditor lists" or payment white/blacklists where available
- **Vigilance Against Scams**: Be alert to phishing emails, SMS messages, and scam calls referencing bank details
- **Unauthorized Mandate Reporting**: Report suspicious payment mandate requests immediately to bank
- **Bank Coordination**: Notify bank about possible credential misuse or identity theft risks
- **Credit Freezes**: Consider credit freezes with reporting agencies to prevent fraudulent accounts
- **Long-term Monitoring**: Monitor credit and financial accounts for years after breach

### For Government & Organizations
- **Least Privilege Access**: Enforce least privilege principle—restrict broad database access based on job necessity
- **Multi-Factor Authentication**: Implement mandatory MFA for all access to sensitive databases like FICOBA
- **Access Logging & Auditing**: Comprehensive logging of all database access with retention for investigation
- **Anomaly Detection**: Implement real-time alerting for anomalous access patterns or bulk data queries
- **Credential Rotation**: Regularly rotate credentials of all staff with database access
- **Threat Intelligence**: Monitor for leaked credentials via threat intelligence feeds
- **Unauthorized Activity Detection**: Alert on access outside normal working hours or patterns

### Incident Response & Remediation
- **Immediate Credential Reset**: Reset all credentials for compromised official and similar access accounts
- **System Isolation**: Temporarily isolate FICOBA from broader network if ongoing threat detected
- **Enhanced Monitoring**: Implement enhanced monitoring of FICOBA during post-incident period

### Communication & Notification
- **Victim Notification**: Notification campaign to 1.2 million affected account holders (underway)
- **Transparency Reports**: Public disclosure of breach scope, data exposed, and remediation steps
- **Guidance Materials**: Provide clear guidance to affected individuals on fraud prevention
- **Support Hotlines**: Establish support mechanisms for affected individuals with questions

### Long-term Security Hardening
- **Zero Trust Architecture**: Implement zero trust principles for sensitive database access
- **Network Segmentation**: Isolate FICOBA and similar sensitive systems
- **Encryption**: Implement encryption for data at-rest and in-transit
- **Access Control Modernization**: Move from basic username/password to multi-factor authentication
- **Security Awareness**: Training for government staff on credential security and phishing risks
- **Vendor Assessment**: Audit third-party vendors with database access
- **Incident Response Planning**: Develop comprehensive incident response procedures for database breaches
- **Regulatory Compliance**: Ensure GDPR and other regulatory compliance for sensitive data

## Resources and References

!!! info "Incident Reports"
    - [Leak of personal data from FICOBA: Bank of France Guidance](https://www.banque-france.fr/fr/actualites/fuite-de-donnees-personnelles-du-fichier-national-des-comptes-bancaires-ficoba-la-banque-de-france)
    - [French bank account data breach affects over a million](https://www.connexionfrance.com/practical/more-than-a-million-people-in-france-hit-by-bank-account-data-breach/771322)
    - [French Government Says 1.2 Million Bank Accounts Exposed - SecurityWeek](https://www.securityweek.com/french-government-says-1-2-million-bank-accounts-exposed-in-breach/)
    - [Attacker gets into France's DB listing all bank accounts - The Register](https://www.theregister.com/2026/02/22/french_bank_hack/)
    - [French Ministry confirms data access to 1.2 Million bank accounts](https://securityaffairs.com/188200/hacking/french-ministry-confirms-data-access-to-1-2-million-bank-accounts.html)
    - [The bank accounts of 1.2 million French people have been consulted](https://leclaireur.fnac.com/article/656786-piratage-du-fisc-votre-compte-bancaire-a-t-il-ete-consulte/)
    - [Single compromised account gave hackers access to 1.2 million French banking records - IT Pro](https://www.itpro.com/security/data-breaches/a-single-compromised-account-gave-hackers-access-to-1-2-million-french-banking-records)
    - [Data breach at French bank registry impacts 1.2 million accounts](https://www.bleepingcomputer.com/news/security/data-breach-at-french-bank-registry-impacts-12-million-accounts/)

---

*Last Updated: February 23, 2026* 