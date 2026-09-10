# US Government Accuses Chinese AI Firms of Distilling Frontier Models
![alt text](images/US.png)

**AI Security**{.cve-chip} **Model Distillation**{.cve-chip} **IP Extraction Risk**{.cve-chip} **Service Abuse**{.cve-chip} **Strategic Competition**{.cve-chip}

## Overview

The U.S. National Security Agency (NSA), Cybersecurity and Infrastructure Security Agency (CISA), and Federal Bureau of Investigation (FBI) issued a joint cybersecurity advisory alleging that China-based AI companies conducted industrial-scale knowledge-distillation campaigns to extract proprietary capabilities from U.S. frontier models.

The advisory names DeepSeek, Moonshot AI, Alibaba, MiniMax, StepFun, and Z.AI, and alleges extraction at the scale of billions of tokens across millions of exchanges since at least late 2024. U.S. agencies assess the activity likely occurred with Chinese government awareness. China publicly rejected the allegations as groundless and characterized distillation as a common and neutral AI-development technique.

This is best categorized as an ongoing strategic AI/IP-extraction and terms-of-service abuse campaign, not a single traditional malware or host-intrusion incident.

## Technical Details

### Technique: Knowledge Distillation

- Knowledge distillation is a legitimate ML practice in which a smaller or less-capable student model learns from outputs of a more-capable teacher model.
- The U.S. advisory distinguishes authorized research from alleged malicious distillation performed at scale without authorization and in violation of provider terms.

### Alleged Targeted Capability Areas

Reported targeting focused on high-value model behaviors such as:

- Advanced reasoning performance
- Coding and technical problem solving
- Specialized/domain capabilities
- Agentic task execution patterns

### Alleged Targeted U.S. Model Families

- Anthropic Claude
- OpenAI GPT
- Google Gemini
- xAI Grok

### Alleged Scale and Timeline

- Activity alleged since at least late 2024.
- Claimed scale: billions of tokens collected through millions of exchanges/requests.

### Alleged Evasion Characteristics

- The advisory describes distributed operations across multiple providers, platforms, accounts, and access pathways.
- Objective of distribution: reduce detectability by avoiding single-account or single-network concentration.

### Attribution and Evidence Context

- The named-company claims represent official U.S. government allegations and assessment.
- Public reports referenced here do not provide independent technical validation of each allegation for every named organization.
- China publicly disputes the allegations.

### Exploitation Status

- Active and ongoing according to U.S. agency assessment.
- No CVE, ransomware family, or classic host/network intrusion vector is central to this incident class.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Incident Class** | Strategic model-capability extraction / service-abuse campaign |
| **Primary Technique** | High-volume knowledge-distillation from frontier-model outputs |
| **Named by U.S. Advisory** | DeepSeek, Moonshot AI, Alibaba, MiniMax, StepFun, Z.AI |
| **Alleged Target Model Families** | Anthropic Claude, OpenAI GPT, Google Gemini, xAI Grok |
| **Alleged Activity Window** | Since at least late 2024 |
| **Alleged Scale** | Billions of tokens across millions of exchanges |
| **Core Abuse Surface** | API/subscription access channels, account ecosystems, query pipelines |
| **Public Dispute Status** | Allegations publicly rejected by China |

## Affected Products

- Frontier-model API and subscription ecosystems exposed to automated high-volume interaction.
- Enterprise AI platforms and cloud-hosted model-access pathways.
- Abuse detection, account integrity, and policy-enforcement systems in AI providers.

## Attack Scenario

1. Operator identifies frontier model capabilities to target (reasoning, coding, domain strengths, agentic outputs).
2. Operator establishes distributed access using many accounts, subscriptions, providers, and network pathways.
3. Large-scale structured prompt campaigns are executed to collect outputs and behavior patterns.
4. Capability probing and guardrail-stress prompting are used to maximize extraction value.
5. Collected interaction datasets are used to train or improve domestic student models.
6. Campaign stays focused on access-channel abuse and terms violations rather than direct provider infrastructure compromise.

## Impact Assessment

=== "Confirmed Public Position"

    - U.S. NSA/CISA/FBI formally issued the allegation and risk assessment
    - Campaign is characterized as systematic and strategic by U.S. agencies

=== "Attribution and Dispute Context"

    - Allegations are official U.S. government claims
    - China publicly disputes the claims and rejects their factual/legal basis
    - No public court finding or universally independent proof confirms every allegation against each named firm

=== "Potential Provider and Market Impact"

    - Extraction of proprietary behaviors may erode frontier-model competitive advantage
    - Large-scale abusive use can increase infrastructure cost and detection burden
    - Distillation at scale may shorten competitor development timelines and reduce R&D/compute costs

=== "Potential National-Security Impact"

    - Advanced AI capability transfer can affect economic competition, intelligence, cyber operations, and dual-use technology balance

## Mitigation Strategies

### Detect and Limit High-Volume Extraction

- Apply strict rate limits, token quotas, concurrency caps, and progressive restrictions across accounts and organizations.
- Detect systematic prompt-variation and capability-probing patterns inconsistent with normal usage.

### Strengthen Account and Subscription Controls

- Enforce MFA for high-volume, premium, enterprise, and administrative accounts.
- Detect account sharing, account farming, subscription abuse, and rapid IP/proxy churn.
- Use risk-based authentication and step-up controls for anomalous behavior.

### Correlate for Distributed Abuse

- Correlate telemetry across identities, API keys, payment methods, devices, IP ranges, geographies, and output-collection behavior.
- Avoid reliance on single-account thresholds for abuse decisions.

### Protect High-Risk Capability Surfaces

- Apply layered safeguards for reasoning, code-generation, agentic, and sensitive-domain outputs.
- Evaluate whether batch export features, response detail depth, and automation interfaces increase distillation risk.
- Consider watermarking or output-governance controls where appropriate.

### Harden Response and Enforcement Operations

- Maintain explicit terms prohibiting unauthorized extraction, scraping, account sharing, and safeguard bypass.
- Build rapid workflows for account suspension, key revocation, traffic shaping, and evidence preservation.
- Coordinate with cloud, identity, and payment providers during abuse disruption.

### Share Threat Intelligence

- Share indicators and behavioral patterns with trusted industry partners and relevant national cyber bodies.
- Establish a formal model-abuse incident-response process alongside traditional cybersecurity response.

## Resources and References

!!! info "Public Reporting and Advisory"
    - [NSA / CISA / FBI Joint Cybersecurity Advisory](https://media.defense.gov/2026/Sep/08/2003992823/-1/-1/1/CSA_CHINA_BASED_AI_COMPANIES_MALICIOUS_DISTILLATION_AGAINST_US.PDF)
    - [SecurityWeek: U.S. agencies warn China is systematically extracting frontier AI capabilities](https://www.securityweek.com/us-agencies-warn-china-is-systematically-extracting-frontier-ai-capabilities/)

---

*Last Updated: September 10, 2026*