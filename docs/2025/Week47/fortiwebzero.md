# FortiWeb OS Command Injection (CVE-2025-58034)
![FortiWeb command injection](images/fortiwebzero.png)

## Description

Fortinet’s FortiWeb Web Application Firewall (WAF) is vulnerable to an authenticated OS command injection flaw (**CVE-2025-58034**). Attackers can execute arbitrary OS commands via crafted HTTP requests or CLI commands, enabling full compromise of the device. This vulnerability poses significant risks to enterprise environments due to its ability to escalate privileges and establish persistence.

---

## Technical Details

| **Component / Area**         | **Details**                                            |
| ---------------------------- | ------------------------------------------------------ |
| **CVE**                      | **CVE-2025-58034**                                     |
| **Vulnerability Type**       | OS Command Injection                                   |
| **Affected Feature**         | FortiWeb Management Interface                          |
| **Attack Vector**            | Crafted HTTP POST requests or CLI commands            |
| **Privilege Level Achieved** | Full Administrative Control                            |

### Vulnerability Details

1. **OS Command Injection** via crafted HTTP requests or CLI commands:
   - Attackers exploit improper input validation in the FortiWeb management interface.
   - Arbitrary OS commands can be executed, enabling privilege escalation and persistence.

### Affected Versions

* 8.0.0–8.0.1
* 7.6.0–7.6.5
* 7.4.0–7.4.10
* 7.2.0–7.2.11
* 7.0.0–7.0.11

---

## Attack Scenario

1. Attacker authenticates to the FortiWeb device (or exploits another vulnerability to gain access).
2. Sends crafted HTTP POST requests or CLI commands to execute arbitrary OS commands.
3. Establishes persistence by creating rogue admin accounts or installing backdoors.
4. With persistence established, the attacker can:

   * Modify WAF policies
   * Disable protections
   * Intercept or manipulate traffic
   * Pivot internally

---

## Impact Assessment

=== "System Compromise"

* Full administrative compromise of FortiWeb
* Ability to disable or tamper with WAF rules
* Long-term persistence via hidden accounts or backdoors
* Potential internal network pivoting
* High risk of sensitive traffic interception or alteration

---

## Mitigation Strategies

### 🔄 Immediate Patching

Upgrade to fixed versions:

* **8.0.2**
* **7.6.6**
* **7.4.11**
* **7.2.12**
* **7.0.12**

### 🌐 Reduce Exposure

* Disable HTTP/HTTPS admin access on internet-facing interfaces.

### 🔍 Detection & Threat Hunting

* Check for **unauthorized admin accounts**.
* Inspect logs for suspicious CLI commands or HTTP POST requests.

### 🔒 Network Hardening

* Restrict management access to internal networks only.

### 📘 CISA KEV Compliance

* Apply patches within required remediation windows.

---

## Resources & References

!!! info "Official & Media Reports"

      * [PSIRT | FortiGuard Labs](https://fortiguard.fortinet.com/psirt/FG-IR-25-513)
      * [Fortinet Woes Continue With Another WAF Zero-Day Flaw](https://www.darkreading.com/vulnerabilities-threats/fortinet-woes-continue-another-waf-zero-day-flaw)
      * [Fortinet confirms second 0-day in just four days • The Register](https://www.theregister.com/2025/11/19/fortinet_confirms_second_fortiweb_0day/)
      * [A second Fortinet FortiWeb zero-day spurs 7-day CISA KEV deadline | SC Media](https://www.scworld.com/news/a-second-fortinet-fortiweb-zero-day-spurs-7-day-cisa-kev-deadline)
      * [NVD - CVE-2025-58034](https://nvd.nist.gov/vuln/detail/CVE-2025-58034)