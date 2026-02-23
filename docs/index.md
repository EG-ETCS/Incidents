---
hide:
  - navigation
  - toc
---

# Today's Security Incidents

<div class="grid cards" markdown>

-   ![honeywell](2026/Week8/images/honeywell.png)

    **CVE-2026-1670 – Authentication Bypass in Honeywell CCTV Cameras**

    **CVE-2026-1670**{.cve-chip} **Authentication Bypass**{.cve-chip} **CCTV Security**{.cve-chip} **Unauthenticated Access**{.cve-chip}

    An authentication bypass flaw in Honeywell CCTV camera models allows attackers to access a password recovery API endpoint without valid credentials. By changing the recovery email to an attacker-controlled address, adversaries can trigger password resets and gain full administrative access to affected devices.

    The vulnerability requires no prior credentials or user interaction—only network reachability of the camera. Supported models include I-HIB2PI-UL, SMB NDAA MVO-3, and PTZ WDR 2MP variants. Exploitation enables unauthorized access to live surveillance feeds, camera controls, and potential network pivoting into adjacent systems.

    [:octicons-arrow-right-24: Read more](2026/Week8/honeywell.md)

-   ![predator](2026/Week8/images/predator.png)

    **Predator Spyware: iOS Mic/Camera Indicator Suppression**

    **Commercial Spyware**{.cve-chip} **iOS Targeting**{.cve-chip} **Surveillance**{.cve-chip} **Covert Recording**{.cve-chip}

    Predator, a sophisticated commercial spyware by Intellexa, can hook into iOS SpringBoard to suppress the green/orange camera and microphone activity indicators, hiding covert surveillance from users. By injecting code into SpringBoard's internal functions and nullifying sensor state update objects, Predator silently disables visual alerts while recording continues undetected.

    Targeting journalists, activists, and political figures, Predator requires kernel-level access and demonstrates how sophisticated spyware subverts fundamental iOS privacy protections. The malware can capture microphone audio, record video, exfiltrate GPS data, and monitor communications without any visual indication to the user.

    [:octicons-arrow-right-24: Read more](2026/Week8/predator.md)

-   ![grandstream](2026/Week8/images/grandstream.png)

    **Critical VoIP Vulnerability in Grandstream GXP1600 Series (CVE-2026-2329)**

    **CVE-2026-2329**{.cve-chip} **Remote Code Execution**{.cve-chip} **VoIP Phone**{.cve-chip} **Call Interception**{.cve-chip}

    A critical unauthenticated stack-based buffer overflow in Grandstream GXP1600 series VoIP phones enables remote code execution with root privileges. By sending a crafted HTTP request to the web API endpoint, attackers can trigger a buffer overflow and execute arbitrary code without any authentication.

    Post-exploitation, attackers extract SIP and local credentials, reconfigure the phone's SIP settings to route calls through malicious proxies, and silently intercept calls while the phone functions normally. These phones serve as stealthy network footholds for eavesdropping on confidential business and government communications.

    [:octicons-arrow-right-24: Read more](2026/Week8/grandstream.md)

-   ![ficoba](2026/Week8/images/FICOBA.png)

    **FICOBA National Bank Account Database Breach (France)**

    **Data Breach**{.cve-chip} **Credential Compromise**{.cve-chip} **Financial Data**{.cve-chip} **Government Database**{.cve-chip}

    A malicious actor used stolen government official credentials to access FICOBA, France's national database recording all bank accounts. Approximately 1.2 million account records were compromised, exposing RIB/IBAN numbers, names, residential addresses, tax IDs, and birth information.

    While no account balances or transaction capability was accessed, the exposure of banking identifiers creates significant risk for fraud, unauthorized direct debits, and identity theft. The breach resulted from insufficient access controls, lack of multi-factor authentication, and inadequate monitoring of sensitive database queries.

    [:octicons-arrow-right-24: Read more](2026/Week8/FICOBA.md)

</div>
