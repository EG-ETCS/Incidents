# CodeBreach – AWS CodeBuild Misconfiguration Vulnerability

![alt text](images/codebreach.png)

**AWS Misconfiguration**{.cve-chip}  **Supply Chain Vulnerability**{.cve-chip}  **Regex Filter Bypass**{.cve-chip}

## Overview
A critical misconfiguration in AWS CodeBuild webhook filters allowed unauthenticated actors to trigger build jobs and access privileged credentials stored in CI/CD environments. 

The vulnerability stemmed from improperly anchored regex patterns in ACTOR_ID filters that were intended to restrict which GitHub users could trigger builds. Instead of matching exact trusted actor IDs, the flawed regex accepted any ID containing an approved ID as a substring. 

This enabled attackers to create GitHub accounts with numeric IDs matching the vulnerable regex pattern and bypass authentication, potentially hijacking AWS-managed GitHub repositories and injecting malicious code into critical supply chain dependencies used globally. 

Although AWS patched the issue before confirmed exploitation, the potential blast radius could have compromised countless users and services relying on affected packages.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Vulnerability Type** | Regex Pattern Validation Flaw (CWE-1025) |
| **Affected Service** | AWS CodeBuild |
| **Component** | Webhook ACTOR_ID filter |
| **Root Cause** | Missing regex anchors (^ and $) |
| **Attack Vector** | Unauthenticated Remote |
| **Authentication Required** | No (attackers create new GitHub accounts) |
| **Complexity** | Low |
| **User Interaction** | Not required |
| **Severity** | Critical (Supply Chain Impact) |
| **Scope of Impact** | Global supply chain dependencies |
| **Exploitation Status** | Patched before confirmed exploitation |

## Affected Products
- AWS CodeBuild
- AWS SDK repositories (aws-sdk-js-v3 and others)
- Any organization using CodeBuild with webhook-triggered builds
- Any software packages dependent on compromised AWS GitHub repositories

![CodeBreach](https://www.datocms-assets.com/75231/1768487001-aws_blog_id_eclipse_v3-1.gif)

## Attack Scenario
1. Attacker analyzes GitHub user IDs of trusted maintainers with CodeBuild access (e.g., 755743)
2. Attacker creates a new GitHub account with a numeric ID containing the trusted ID as a substring (e.g., 226755743), exploiting the unanchored regex pattern that checks if ID contains "755743" rather than exact match
3. Attacker triggers a CodeBuild job for a restricted AWS repository using the crafted account, bypassing ACTOR_ID webhook filter validation
4. Build process executes with access to privileged credentials; attacker extracts GitHub Personal Access Tokens (PATs) and other secrets from build environment memory
5. Using harvested admin credentials, attacker gains repository access to inject malicious code into widely distributed packages or build artifacts, achieving supply chain compromise affecting dependent services globally

![CodeBreach Attack Flow](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgVXz5Nse8GqK_6PShb4z-had2gOEGp-fPzqg_sZjFfwyK3I1s0ZccAh4rKQ2A2hANfMtzlhACyJVSdCFDBQkJd0_NOs93Y4-n7hN8w7840RZO0qD1RmaWNWFm3IroQWzLIg6YWduLwB-8VXkKLNaJl3FSc-85r_ldNinz06ZfqId1_NnLuJS6RNaAtgQgD/s1600-e365/repo.gif)

## Impact Assessment

=== "Integrity"
    * Injection of malicious code into AWS SDK repositories and packages
    * Unauthorized modification of build artifacts and deployment packages
    * Compromise of software supply chain affecting global user base
    * Alteration of build configurations and deployment processes
    * Contamination of critical infrastructure dependencies

=== "Confidentiality"
    * Exposure of GitHub Personal Access Tokens (PATs) with repository admin privileges
    * Theft of AWS credentials and secrets stored in build environments
    * Access to private repository contents and source code
    * Disclosure of internal build processes and configuration details
    * Unauthorized access to credentials used for package distribution

=== "Availability"
    * Potential widespread disruption of services dependent on compromised packages
    * Build pipeline hijacking and denial of legitimate builds
    * Service unavailability for organizations relying on infected packages
    * Operational impact from supply chain compromise remediation
    * Cascading failures across dependent software ecosystems

## Mitigation Strategies

### Immediate Actions
- Audit all CodeBuild webhook configurations to identify unanchored regex patterns
- Implement anchored regex filters using ^ and $ delimiters for all ACTOR_ID checks
- Rotate and revoke all GitHub Personal Access Tokens and AWS credentials exposed to build environments
- Review build logs for suspicious trigger patterns and unauthorized access attempts
- Enable webhook filtering validation to ensure only exact matches are accepted

### Short-term Measures
- Restrict pull request builds from untrusted sources from triggering privileged build processes
- Generate unique, least-privilege Personal Access Tokens (PATs) for each CI/CD pipeline
- Implement role-based access controls limiting build environment credential exposure
- Add Pull Request Comment Approval build gates requiring maintainer review before execution
- Enable audit logging for all webhook events and build triggers

### Monitoring & Detection
- Monitor for CodeBuild webhook triggers from unexpected or newly created GitHub accounts
- Alert on extraction or exposure of credentials in build environment logs
- Track for suspicious commits to AWS repositories from unfamiliar accounts
- Monitor for unauthorized repository access using harvested credentials
- Implement anomaly detection for build job patterns and credential usage
- Alert on changes to webhook filter configurations

### Long-term Solutions
- Establish secure credential management using AWS Secrets Manager integration with CodeBuild
- Implement isolated, unprivileged accounts for build system access with minimal required permissions
- Use temporary credentials with short TTLs instead of long-lived Personal Access Tokens
- Conduct regular audits of CI/CD configurations to identify misconfiguration risks
- Establish supply chain security best practices and automated configuration validation
- Implement code signing and artifact verification for all build outputs
- Maintain comprehensive audit trails and security monitoring across build pipelines
- Regular penetration testing of CI/CD infrastructure and webhook security

## Resources and References

!!! info "Official Documentation"
    - [CodeBreach: Supply Chain Vulnerability & AWS CodeBuild Misconfiguration - Wiz Blog](https://www.wiz.io/blog/wiz-research-codebreach-vulnerability-aws-codebuild)
    - [AWS CodeBuild Misconfiguration Exposed GitHub Repos to Potential Supply Chain Attacks](https://thehackernews.com/2026/01/aws-codebuild-misconfiguration-exposed.html)
    - [Regex Filter Flaw in AWS CodeBuild Exposed GitHub Repositories to Supply Chain Attacks - LavX News](https://news.lavx.hu/article/regex-filter-flaw-in-aws-codebuild-exposed-github-repositories-to-supply-chain-attacks)
    - [Unanchored ACCOUNT_ID Webhook Filters for CodeBuild - AWS Security](https://aws.amazon.com/security/security-bulletins/rss/2026-002-aws/)
    - [AWS CodeBuild 'CodeBreach' Flaw Exposed GitHub Repos to Hijacking](https://www.webpronews.com/aws-codebuild-codebreach-flaw-exposed-github-repos-to-hijacking/)
    - [A Simple CodeBuild Flaw Put Every AWS Environment at Risk - The Register](https://www.theregister.com/2026/01/15/codebuild_flaw_aws/)
