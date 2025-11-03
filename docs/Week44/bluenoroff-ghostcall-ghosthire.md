# BlueNoroff GhostCall and GhostHire Campaigns

**APT Campaign**{.cve-chip}
**AI-Enhanced**{.cve-chip}
**Cryptocurrency Theft**{.cve-chip}
**Social Engineering**{.cve-chip}

---

## Description

BlueNoroff (a subgroup of the North-Korean Lazarus Group) launched two AI-enhanced intrusion campaigns:

- **GhostCall** – Social-engineering attacks on macOS users posing as venture-capital investors arranging fake "investment meetings."
- **GhostHire** – Fake recruiter outreach to blockchain developers distributing infected "test-task" repositories.

Both share command infrastructure and malware families developed or optimized using generative AI.

## Technical Details

### Delivery Methods
- **Telegram contacts** → fake Zoom/Teams meeting pages (GhostCall) or trojanized GitHub repos (GhostHire)

### Payloads
New malware classes designed for:
- **Cryptocurrency theft**
- **Telegram data exfiltration** 
- **Browser credential harvesting**

### AI Usage
- **Automatic malware code generation** in multiple languages
- **Realistic social-engineering text/video creation**
- **AI-driven victim selection and intelligence analysis**

## Attack Scenario

### Initial Contact
- **GhostCall**: Attackers pose as investors via Telegram using compromised entrepreneur accounts
- **GhostHire**: Attackers impersonate recruiters and send "test tasks"

### Social Engineering
Victims are guided to fake meeting pages or GitHub repos.

### Execution / Infection
- **GhostCall**: Victims asked to "update the client"
- **GhostHire**: Victims asked to run a test script
- Running the file triggers download and execution of malware

### Post-Exploitation / Lateral Movement
- Data and credentials stolen
- Cryptocurrency wallets drained
- Supply chain partners targeted using stolen identities

## Impact

- **Compromise** of executive / developer endpoints
- **Theft** of digital assets and sensitive credentials
- **Lateral spread** through trusted partners / vendors
- **Reputational and financial losses**
- **Harder forensic analysis** due to polymorphic, AI-generated code

## Mitigations

### User Awareness
- Verify meeting / recruiter requests through separate channels
- Avoid installing "updates" from links

### Endpoint Protection
- Deploy EDR covering macOS + Windows
- Block unsigned installers and monitor for unknown C2 traffic

### Developer Hygiene
- Execute untrusted code only in sandboxes or VMs
- Validate GitHub sources and commits

## Resources

1. [DPRK's BlueNoroff Expands Scope of Crypto Heists](https://www.secureworks.com)
2. [Researchers Expose GhostCall and GhostHire: BlueNoroff's New Malware Chains](https://www.kaspersky.com)
3. [GhostCall and GhostHire — two campaigns by BlueNoroff](https://securelist.com)
4. [Kaspersky: BlueNoroff targets executives on Windows and macOS using AI-driven tools](https://www.kaspersky.com)

---