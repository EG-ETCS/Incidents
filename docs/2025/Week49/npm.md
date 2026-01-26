# Contagious Interview (2025 npm-registry wave)

**Supply-Chain / npm Registry Campaign**{.campaign-chip}  
**Loader Malware (OtterCookie / BeaverTail merge)**{.campaign-chip}  
**Developer Environment Compromise**{.campaign-chip}

## Overview

"Contagious Interview" is a 2025 wave of malicious npm packages that added 197 malicious packages to the registry and were downloaded over ~31,000 times. The packages act as loaders: when installed they contact attacker-controlled staging sites (commonly hosted on Vercel) to fetch and execute a cross-platform malware payload (an updated OtterCookie variant with BeaverTail features). Attackers used recruiter-style social engineering and "coding test" lures to get developers to install the packages.

## Technical Specifications

| **Attribute**           | **Details**                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| **Campaign Name**       | Contagious Interview (2025 npm wave)                                        |
| **Vector**              | Malicious npm packages / typosquatting / cloned GitHub repos                |
| **Packages Added**      | 197 malicious packages                                                      |
| **Downloads Observed**  | ~31,000                                                                     |
| **Malware Family**      | OtterCookie (updated) with BeaverTail features                              |
| **Delivery / Staging**  | Initial loader on npm → fetch payload from Vercel staging sites / GitHub    |
| **Targets**             | Developer machines (Windows, Linux, macOS), build agents, CI pipelines      |
| **Capabilities**        | Remote shell/C2, data exfiltration, credential & wallet theft, persistence  |

## Technical Details

- Social-engineering lures: attackers pose as recruiters on LinkedIn/Telegram/Discord and provide “test assignments” that require installing or running code.  
- Malicious packages are often plausible names, typosquatting, or dev-tool style packages to avoid suspicion.  
- The npm package acts as a loader: on install/run it contacts a Vercel-hosted staging site (e.g., tetrismic.vercel[.]app) to download the real payload (often from attacker-controlled GitHub).  
- Payloads are cross-platform and implement C2, credential harvesting (browsers, wallets), file exfiltration, and persistence.  
- Infection can propagate via shared repos, CI/CD pipelines, or build artifacts if the malicious dependency is committed or cached.

## Attack Scenario

1. Attacker recruits or lures developer with a job/test assignment linking to a repo or npm package.  
2. Developer clones the repo or installs the npm package locally (often outside containers).  
3. Loader executes, fetches the real payload from staging infrastructure, and runs it.  
4. Payload establishes C2, harvests credentials and wallet data, exfiltrates files, and persists.  
5. Compromise spreads to organizational assets via shared code, CI jobs, or developer workstations.

![](images/npm1.png)
## Impact Assessment

=== "Credential & Wallet Theft"
    * Browser-stored credentials and crypto-wallet secrets (seed phrases, wallet files) may be exfiltrated.
=== "Remote Access & Long-Term Backdoor"
    * Attackers can gain persistent remote shell access and full control of developer machines.
=== "Supply-Chain & Organizational Risk"
    * Malicious packages included in projects can compromise downstream developers, CI systems, and production builds — potentially causing widespread organizational impact.

## Mitigations

### Audit & Restrict
- Audit dependencies before installing; avoid unknown packages and watch for typosquatting.  
- Restrict installation of untrusted packages in developer and CI environments.

### Isolation & Hardening
- Run untrusted installs in containers, sandboxes, or ephemeral VMs, not on primary developer workstations or build hosts.  
- Harden CI/CD: pin dependencies, use reproducible builds, restrict network egress during builds, and scan artifacts.

### Tooling & Detection
- Use SCA/dependency-scanning and publisher reputation tools to detect malicious packages.  
- Monitor developer endpoints and CI for unexpected network connections to staging hosts (Vercel, GitHub) and unusual process activity.

### Response
- Rotate credentials and wallet keys if a compromise is suspected.  
- Perform forensics on affected hosts and purge malicious packages from projects and registries.

## Resources & References

!!! info "Coverage & Reports"
    * [Contagious Interview campaign expands with 197 npm packages spreading new OtterCookie malware ](https://securityaffairs.com/185170/apt/contagious-interview-campaign-expands-with-197-npm-ppackages-spreading-new-ottercookie-malware.html)
    * [North Korean Hackers Deploy 197 npm Packages to Spread Updated OtterCookie Malware — Threat Radar / OffSeq ](https://radar.offseq.com/threat/north-korean-hackers-deploy-197-npm-packages-to-sp-0425e4ed)
    * [North Korean Hackers Abuse npm, GitHub, and Vercel to Spread OtterCookie Malware](https://gbhackers.com/ottercookie-malware/)
    * [North Korean Hackers Deploy 197 npm Packages to Spread Updated OtterCookie Malware](https://thehackernews.com/2025/11/north-korean-hackers-deploy-197-npm.html)