# Multiple GitLab Vulnerabilities Enable 2FA Bypass and DoS Attacks

**CVE-2026-0723**{.cve-chip} **2FA Bypass**{.cve-chip} **CWE-252**{.cve-chip} **CVSS 7.4**{.cve-chip} **WebAuthn**{.cve-chip} **Supply Chain**{.cve-chip}

## Overview

A cluster of critical vulnerabilities affecting GitLab Community Edition (CE) and Enterprise Edition (EE) has been disclosed, with the most severe enabling attackers to bypass two-factor authentication (2FA) protections and gain unauthorized access to protected repositories, CI/CD pipelines, and sensitive source code. The primary vulnerability (CVE-2026-0723) stems from an unchecked return value in GitLab's authentication services, allowing attackers with knowledge of a victim's credential ID to submit forged WebAuthn device responses that circumvent multi-factor authentication requirements. Additional vulnerabilities in the same patch cycle enable denial-of-service attacks targeting GitLab instances, creating availability risks for development teams relying on GitLab for version control, continuous integration, and DevOps workflows.

GitLab serves as the backbone infrastructure for over 30 million registered users across 100,000+ organizations, managing source code repositories, automated testing and deployment pipelines, container registries, and security scanning workflows. The platform's central role in software development lifecycles—from initial code commits to production deployments—makes it a high-value target for threat actors seeking to inject malicious code into software supply chains, steal intellectual property, or disrupt critical development operations. Two-factor authentication represents a cornerstone security control protecting GitLab accounts from credential stuffing, phishing, and password spray attacks; vulnerabilities enabling 2FA bypass fundamentally undermine this protection layer.

The CVE-2026-0723 authentication bypass vulnerability exploits improper handling of WebAuthn authentication flows, specifically when processing device credential responses during the second factor verification stage. GitLab's authentication logic fails to properly validate return values from WebAuthn operations, allowing attackers to craft forged responses that the system incorrectly accepts as valid second-factor proof. The attack requires knowledge of a target user's credential ID—a value that, while not secret in the traditional sense, can be obtained through social engineering, OSINT reconnaissance of public repositories, or exploitation of information disclosure vulnerabilities. Once armed with a credential ID, attackers can programmatically generate fake 2FA responses and bypass authentication controls to access the victim's account with only password knowledge.

GitLab released emergency security patches addressing these vulnerabilities in versions 18.8.2, 18.7.2, and 18.6.4 on January 2026. Organizations running unpatched GitLab instances face immediate risks of account compromise, repository exfiltration, CI/CD pipeline manipulation for supply chain attacks, and denial-of-service disruptions affecting development team productivity. The vulnerabilities affect all GitLab deployment models including self-managed installations, dedicated instances, and multi-tenant SaaS environments, requiring coordinated patching across diverse infrastructure configurations.

---

## Vulnerability Specifications

| **Attribute**              | **Details**                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| **Primary CVE ID**         | CVE-2026-0723 (2FA Bypass)                                                  |
| **Vulnerability Type**     | Authentication Bypass (Two-Factor Authentication)                           |
| **CWE Classification**     | CWE-252: Unchecked Return Value                                             |
| **Affected Products**      | GitLab Community Edition (CE), GitLab Enterprise Edition (EE)               |
| **Vulnerable Versions**    | 18.6.0 - 18.6.3, 18.7.0 - 18.7.1, 18.8.0 - 18.8.1                          |
| **Fixed Versions**         | 18.6.4, 18.7.2, 18.8.2                                                      |
| **Attack Vector**          | Network (Remote)                                                            |
| **Attack Complexity**      | Medium (Requires credential ID knowledge)                                   |
| **Privileges Required**    | None (Knowledge of username/password + credential ID)                       |
| **User Interaction**       | None                                                                        |
| **Scope**                  | Changed (Access beyond intended authentication boundaries)                  |
| **Confidentiality Impact** | High (Access to private repositories, source code, secrets)                 |
| **Integrity Impact**       | High (Ability to modify code, CI/CD pipelines, container images)            |
| **Availability Impact**    | Low (Primary impact on confidentiality/integrity)                           |
| **CVSS 3.1 Base Score**    | 7.4 (High) for 2FA Bypass                                                   |
| **Public Disclosure Date** | January 2026                                                                |
| **Patch Availability**     | January 2026 (Versions 18.8.2, 18.7.2, 18.6.4)                              |

---

## Technical Details

### GitLab Authentication Architecture

GitLab implements multi-layered authentication supporting various second-factor methods. The authentication flow consists of three primary steps:

**Step 1: Primary Authentication** - Users submit their username and password credentials. GitLab's authentication service validates these credentials against the database, checks account status, and proceeds to second-factor verification if valid.

**Step 2: Two-Factor Authentication** - GitLab supports multiple 2FA methods including TOTP (Time-based One-Time Password), WebAuthn (FIDO2 Hardware Keys), legacy U2F, and SMS/backup codes. The WebAuthn flow is particularly vulnerable: the browser requests a challenge, the user activates their security key, the device signs the challenge with its private key, the browser sends the signed response to GitLab, and GitLab attempts to validate the response. The vulnerability exists in this validation step where unchecked return values allow forged responses to bypass authentication.

**Step 3: Session Establishment** - Upon successful 2FA verification, GitLab creates an authenticated session. However, the bypass vulnerability allows attackers to gain unauthorized access without valid second-factor proof.

### CVE-2026-0723: WebAuthn 2FA Bypass Technical Analysis

The vulnerability exists in GitLab's WebAuthn authentication handler, specifically in how it processes device credential assertions. The core issue is an **unchecked return value** in the validation function. When GitLab validates WebAuthn assertions, the validation function may return null or false values under certain error conditions, but the authentication flow doesn't properly verify this result before proceeding to grant access.

The vulnerable code pattern proceeds with session creation even when validation returns nil or false, rather than explicitly checking for successful validation. Additionally, exception handling may not properly propagate errors, returning nil instead of explicit false values. This allows attackers to submit forged WebAuthn responses that the system incorrectly accepts as valid.

### Exploitation Mechanics

**Attack Prerequisites:**

1. **Valid Username/Password** - Obtained through phishing, credential dumps, password spraying, or social engineering
2. **Credential ID** - WebAuthn credential identifier, which can be obtained via:
    - OSINT reconnaissance (sometimes exposed in client-side JavaScript)
    - Information disclosure vulnerabilities
    - Social engineering targeting IT support personnel
    - Network traffic analysis of authentication flows

**Exploitation Process:**

The attack follows a two-step process. First, the attacker performs primary authentication using the compromised username and password, which triggers the 2FA challenge. Second, the attacker submits a forged WebAuthn response containing the known credential ID, fake client data, fabricated authenticator data, and an invalid signature. Due to the unchecked return value vulnerability, GitLab incorrectly accepts this forged response and grants authenticated access.

### Obtaining Credential IDs

Attackers can acquire WebAuthn credential IDs through multiple vectors:

**Information Disclosure** - Client-side JavaScript may expose credential IDs in browser console logs, network traffic visible in DevTools, or debugging output inadvertently left in production code.

**Network Traffic Analysis** - Credential IDs transmitted during legitimate authentication flows can be captured through network monitoring, even over HTTPS connections where they appear in decrypted browser-to-server communications.

**Social Engineering** - Attackers may contact IT support personnel pretending to troubleshoot security key issues, asking support staff to verify credential IDs and inadvertently confirming guessed values.

### CVE-2026-0724: Denial of Service via GraphQL Query Complexity

A secondary vulnerability enables DoS attacks through GraphQL query complexity exhaustion. Attackers can craft deeply nested GraphQL queries that request data across multiple resource relationships (projects → pipelines → jobs → artifacts → metadata). These queries cause exponential resource consumption as GitLab attempts to resolve each nested level, eventually exhausting server memory and CPU resources. This leads to service degradation or complete unavailability for legitimate users attempting to access repositories or CI/CD pipelines.


---

## Attack Scenario: SaaS Provider Supply Chain Compromise via GitLab 2FA Bypass

**Scenario Context:**

CloudBridge Solutions, a rapidly growing Software-as-a-Service provider with 8,500 enterprise customers, develops cloud-based business intelligence and analytics platforms generating $420M in annual recurring revenue. The company's engineering team of 450 developers relies exclusively on self-hosted GitLab Enterprise Edition (version 18.8.1) for source code management, CI/CD automation, container registry, and security scanning. Their GitLab instance manages 2,700+ repositories containing proprietary algorithms, customer data processing logic, API integration code, and infrastructure-as-code configurations for AWS deployments serving millions of end-users.

CloudBridge implemented mandatory two-factor authentication across all GitLab accounts in 2024 following a security audit, requiring developers to use WebAuthn-compliant hardware security keys (YubiKey 5 series) for access to production code repositories. The security team viewed 2FA as their primary defense against credential-based attacks, given the high rate of phishing attempts targeting their engineering workforce.

In December 2025, a sophisticated threat actor group (tracked as "SupplyShift") specializing in software supply chain attacks identified CloudBridge as a high-value target whose customer base included financial institutions, healthcare providers, and government agencies.

**Phase 1: Reconnaissance & Credential Harvesting (Week 1-2)**

SupplyShift conducted extensive OSINT reconnaissance on CloudBridge's engineering team through LinkedIn profiles, GitHub activity, conference attendee lists, and credential dump databases. The reconnaissance yielded 847 email/password combinations for CloudBridge employees from historical breaches, with 23 potentially valid credentials for GitLab accounts.

Targeted credential stuffing attacks against CloudBridge's self-hosted GitLab instance discovered 3 valid username/password combinations for developer accounts with 2FA enabled. However, 2FA protection blocked immediate access, requiring WebAuthn hardware key verification.

**Phase 2: Credential ID Discovery & 2FA Bypass (Week 3)**

To bypass WebAuthn 2FA, SupplyShift deployed a fake "Git Productivity Tools" Chrome extension promoted on developer forums. The malicious extension captured WebAuthn credential IDs during legitimate 2FA authentications by 17 CloudBridge developers who installed the extension, building a database mapping GitLab usernames to credential IDs.

On December 18, 2025, SupplyShift exploited CVE-2026-0723 to bypass 2FA for a Senior Backend Developer account with maintainer permissions on core repositories. The attack succeeded within minutes, submitting a forged WebAuthn response that GitLab incorrectly accepted due to unchecked return values in the authentication validation logic.

**Phase 3: Repository Reconnaissance & Supply Chain Attack Planning (Week 3-4)**

With authenticated access, SupplyShift conducted extensive reconnaissance across 47 private repositories, including the core API gateway handling 50M+ requests daily, customer data analytics engines, authentication services, infrastructure-as-code configurations, and ML pipelines.

The attackers identified critical supply chain injection opportunities through NPM and PyPI dependencies, container base images, GitLab CI/CD pipelines with automated production deployments, and Terraform modules managing AWS resources for 8,500 customer tenants.

**Phase 4: Malicious Code Injection & Supply Chain Compromise (Week 5-6)**

SupplyShift executed a sophisticated supply chain attack by modifying the core API gateway repository's CI/CD pipeline configuration. The malicious modifications injected backdoor code during the build process while suppressing security scanning results to avoid detection.

The injected backdoor provided SupplyShift with authentication token interception for all enterprise customer accounts, customer data exfiltration capabilities, persistent access to CloudBridge's production infrastructure, and lateral movement capabilities across customer tenant environments.

**Phase 5: Production Deployment & Widespread Compromise (Week 7)**

The malicious code successfully passed through CloudBridge's CI/CD pipeline and deployed to production on December 29, 2025. The backdoor activated across 47 Kubernetes pods handling production traffic, with legitimate functionality remaining unchanged to avoid suspicion.

Over 14 days, the backdoor compromised 3.2 million authentication tokens for enterprise customer accounts, exfiltrated 847 GB of customer business data including analytics reports and financial dashboards, captured 12,400 API keys for customer integrations with AWS, Salesforce, and Microsoft 365, and obtained credentials for 127 CloudBridge production systems.

---

## Impact Assessment

### Supply Chain Attack Amplification

GitLab compromise enables supply chain attacks with cascading impact across customer ecosystems:

=== "Technical Impact"
    - **Source Code Theft**: Complete exfiltration of proprietary algorithms, business logic, intellectual property
    - **CI/CD Pipeline Manipulation**: Injection of malicious code automatically deployed to production environments
    - **Secrets Exposure**: Access to API keys, database credentials, cloud provider access keys stored in GitLab
    - **Container Registry Poisoning**: Malicious container images distributed to production Kubernetes clusters
    - **Infrastructure-as-Code Compromise**: Terraform/CloudFormation templates modified to create backdoor access
    - **Dependency Confusion**: Malicious packages injected into private package registries

=== "Business Impact"
    - **Intellectual Property Loss**: Theft of source code, algorithms, trade secrets valued at millions to billions
    - **Competitive Disadvantage**: Competitors obtaining proprietary technology and business strategies
    - **Customer Trust Erosion**: Loss of confidence in software security and supply chain integrity
    - **Revenue Losses**: Customer churn, contract cancellations, inability to acquire new customers post-breach
    - **Regulatory Penalties**: GDPR, HIPAA, SOX violations for inadequate security controls
    - **Legal Liability**: Lawsuits from customers affected by supply chain compromise

=== "Sector-Specific Risks"
    - **SaaS Providers**: Multi-tenant platform compromises affecting thousands of downstream customers
    - **Open Source Projects**: Malicious commits to widely-used libraries affecting millions of applications
    - **Financial Services**: Trading algorithms, risk models, customer data processing logic exposure
    - **Healthcare**: Telehealth platforms, EHR integrations, medical device software compromised
    - **Critical Infrastructure**: SCADA systems, utility management software, industrial control logic
    - **Government**: Classified codebases, defense contractor projects, citizen-facing services

### Authentication Bypass Risk Profile

2FA bypass fundamentally undermines security assumptions across enterprise environments:

**Organizations Affected:**

- **30 million+ GitLab users** worldwide across 100,000+ organizations
- **Self-hosted GitLab instances** (versions 18.6.0-18.6.3, 18.7.0-18.7.1, 18.8.0-18.8.1)
- **Multi-tenant SaaS environments** requiring emergency patching
- **Managed service providers** hosting GitLab for multiple clients

**High-Value Targets:**

- **Open Source Maintainers**: Compromise of critical libraries (Log4j, OpenSSL, Kubernetes components)
- **Fortune 500 Engineering Teams**: Access to proprietary product codebases
- **Government Contractors**: Defense, intelligence, critical infrastructure projects
- **Financial Institutions**: Trading platforms, payment processing systems, banking infrastructure
- **Healthcare Organizations**: EHR systems, medical device firmware, telehealth platforms

---

## Mitigation Strategies

### Immediate Actions (Emergency Response)

**Priority 1: Patch Deployment**

Organizations must immediately upgrade to patched GitLab versions: 18.6.4, 18.7.2, or 18.8.2 depending on their current release branch. Before applying patches, create full backups of GitLab data and configurations. After installation, verify the patch version and restart all GitLab services. Monitor the upgrade process for errors and validate that authentication systems function correctly post-patch.

**Priority 2: Threat Hunting & Forensic Analysis**

Review authentication logs for suspicious patterns indicating potential CVE-2026-0723 exploitation. Key indicators include unusually fast 2FA verification times (under 0.5 seconds versus typical 2-5 seconds for physical keys), repeated authentication attempts from single IP addresses, logins from unexpected geographic locations, non-standard user agents suggesting automation, and WebAuthn responses with suspicious authenticator data characteristics.

For any suspicious events identified, immediately force password resets for affected accounts, revoke all active sessions, audit recent code commits for malicious changes, review repository access patterns, check for unauthorized personal access token creation, and examine CI/CD pipeline modifications.

**Priority 3: Account Security Hardening**

Implement immediate compensating controls including mandatory password resets for all users, revocation of all active sessions across the platform, audit and potential revocation of recently-created personal access tokens with write permissions, enforcement of 2FA requirements with zero grace period, disabling of password authentication for Git operations (requiring SSH keys or personal access tokens), and temporary restriction of project export functionality to prevent mass data exfiltration.

### Long-Term Security Enhancements

**Enhanced Authentication Controls**

Configure GitLab to enforce strict authentication policies including mandatory 2FA for all users with no grace period, reduced session expiration timeouts (24 hours maximum), rate limiting on authentication endpoints to prevent brute force attacks, IP allowlisting for administrative accounts, and disabled single sign-on auto-provisioning to prevent unauthorized account creation.

**Supply Chain Security Controls**

Implement secure CI/CD pipeline practices including mandatory security scanning stages (dependency scanning, SAST, secret detection) before builds, integrity hash verification for build scripts and artifacts, locked dependency versions to prevent supply chain injection, manual approval requirements for production deployments, and comprehensive audit logging of all pipeline executions and modifications.

**Monitoring & Detection**

Deploy continuous security monitoring focusing on authentication event analysis, integration with SIEM platforms for real-time alerting, automated detection of suspicious 2FA patterns, geographic anomaly detection for user logins, user agent analysis to identify automation attempts, and correlation of authentication events with code commits and repository access patterns. Establish alert thresholds and response procedures for high-severity security events.

**Organizational Security Practices**

Conduct regular security awareness training for development teams on phishing recognition and credential protection, implement least-privilege access principles for repository permissions, establish code review requirements for all commits to sensitive repositories, maintain an inventory of WebAuthn credentials associated with privileged accounts, and develop incident response playbooks specifically addressing supply chain compromise scenarios.


## Resources

!!! info  "Security Research & Analysis"
    - [Zoom and GitLab Release Security Updates Fixing RCE, DoS, and 2FA Bypass Flaws](https://thehackernews.com/2026/01/zoom-and-gitlab-release-security.html)
    - [GitLab warns of high-severity 2FA bypass, denial-of-service flaws](https://www.bleepingcomputer.com/news/security/gitlab-warns-of-high-severity-2fa-bypass-denial-of-service-flaws/)
    - [Multiple GitLab Vulnerabilities Enable 2FA Bypass and Denial-of-Service Attacks - Cyber Security News](https://cyberpress.org/multiple-gitlab-vulnerabilities-enable-2fa-bypass-and-denial-of-service-attacks/)
    - [Multiple GitLab Vulnerabilities Enables 2FA Bypass and DoS Attacks](https://cybersecuritynews.com/gitlab-vulnerabilities-enables-2fa-bypass-and-dos-attacks/)
    - [GitLab Security Update Fixes Critical Vulnerabilities CVE-2026-0723](https://www.redhotcyber.com/en/post/gitlab-security-update-fixes-critical-vulnerabilities-cve-2026-0723/)
    - [GitLab Patch Release: 18.8.2, 18.7.2, 18.6.4 | GitLab](https://about.gitlab.com/releases/2026/01/21/patch-release-gitlab-18-8-2-released/)

---

*Last Updated: January 22, 2026* 
