# Super Value Co. Ransomware Breach

**Qilin ransomware group — data leak & extortion**{.cve-chip}

## Description

Super Value Co., a Japanese retail chain operating supermarkets and household goods stores, has allegedly been compromised by the Qilin ransomware group.

Qilin posted samples of internal company documents on its dark web leak portal, asserting full data theft and threatening full publication unless a ransom is paid.

The exposed samples include financial, operational, and employee-related documents — a classic multi-extortion tactic to pressure the victim publicly.

## Technical Details

- **Attack Vector:** Not yet publicly disclosed; likely initial access through phishing, exposed RDP/VPN, or exploited service vulnerabilities (based on Qilin’s known TTPs).
- **Malware Used:** Qilin’s proprietary Agenda ransomware variant (written in Go or Rust, configurable, capable of terminating services and disabling security tools).
- **Encryption & Exfiltration:** Qilin uses a double-extortion model — exfiltrate first, then encrypt. Exfiltrated data is stored on attacker-controlled cloud or self-hosted infrastructure before leak site posting.
- **Data Exposed:** Internal documents, accounting files, monthly profit/loss reports, payrolls, and personal data (names, addresses, dates of birth, job roles, work schedules).
- **Leak Sample Proof:** Screenshots and file samples consistent with corporate documentation — performance reports, cash leakage reports, and HR data.

## Attack Scenario

- **Initial Access:** Phishing email or exploitation of an unpatched VPN/RDP gateway.
- **Privilege Escalation & Lateral Movement:** Qilin actors use Cobalt Strike, RDP, or PsExec to move through the network.
- **Data Collection & Exfiltration:** Sensitive financial and HR data compressed and uploaded to external servers (often Mega, anonfiles, or attacker infrastructure).
- **Encryption:** Ransomware payload deployed network-wide; Windows services and backups disabled.
- **Extortion Stage:** Samples uploaded to Qilin leak site → victim contacted via Tor-based portal.
- **Public Exposure:** Leak portal entry published with partial proof-of-data (current stage).

## Impact

- **Data Exposure:** Sensitive employee and financial data leaked — high identity theft risk.
- **Operational Disruption:** Potential IT and payment system outages (not yet confirmed).
- **Reputational Damage:** Severe — public exposure on darknet portal with Japanese press attention.
- **Financial Loss:** Possible ransom payment, forensic and regulatory costs.

## Mitigations

- **Ransom Decision:** Follow national guidance — do not pay; paying does not guarantee deletion and funds criminal activity.
- **Network Hardening:** Disable unused RDP/VPN accounts; enforce MFA on all remote access.
- **Patch Management:** Review systems for known vulnerabilities (esp. Citrix, Fortinet, and VMware — often exploited by Qilin).
- **Backup & Recovery:** Ensure offsite, immutable backups exist and are periodically tested.

## Resources

1. [Qilin Ransomware Claims Hack on Japan’s Super Value Supermarket, Leaks Payroll & P&L Data](https://meterpreter.org/qilin-ransomware-claims-hack-on-japans-super-value-supermarket-leaks-payroll-pl-data/)
2. [Japan’s supermarkets got hacked, say Russian hackers | Cybernews](https://cybernews.com/security/qilin-super-value-japan-breach/)
3. [Qilin Ransomware: Tactics, Attack Methods & Mitigation Strategies](https://www.group-ib.com/blog/qilin-ransomware/)
