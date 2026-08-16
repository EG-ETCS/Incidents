# Rogue Wi-Fi Network on Delta Flight 591
![alt text](images/Delta.png)

**Rogue Access Point**{.cve-chip} **In-Flight Wi-Fi Spoofing**{.cve-chip} **Potential Phishing**{.cve-chip} **Deauthentication Suspicion**{.cve-chip} **Aviation Cybersecurity**{.cve-chip}

## Overview

An unauthorized Wi-Fi network was reportedly observed on Delta Flight 591 (Las Vegas to Atlanta) shortly after DEF CON 34. The network name "Delta WiFi Fast" appears to have been chosen to resemble legitimate in-flight service branding.

Delta stated that the rogue network was not provided, operated, or supplied by Delta. Cabin crew reportedly disabled onboard Wi-Fi for about 30 minutes after detection of suspicious activity.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Incident Type** | Suspected rogue access point / Wi-Fi spoofing in aviation passenger network context |
| **Observed Rogue SSID** | "Delta WiFi Fast" (reported) |
| **Target Surface** | Passenger in-flight Wi-Fi environment |
| **Suspected Technique** | Potential deauthentication/interference followed by fake SSID broadcast (not fully confirmed) |
| **Suspected Objective** | Induce passenger connections to rogue captive portal/phishing workflow |
| **Potential Data at Risk** | Credentials and user-entered information on fraudulent login pages |
| **Operational Response** | Crew temporarily disabled Wi-Fi; incident investigated with law enforcement/regulators |
| **Confirmation Status** | Presence of unauthorized network reported; full attack chain details remain unconfirmed publicly |

## Affected Products

- Passenger Wi-Fi users on affected flight segment
- In-flight connectivity environments vulnerable to SSID spoofing confusion
- Airline operational and security teams handling rogue wireless events

## Attack Scenario

1. An attacker brings a wireless-capable device onboard the aircraft.
2. A rogue SSID resembling the legitimate Delta Wi-Fi network is broadcast.
3. Wireless interference or deauthentication may be used to degrade legitimate connectivity (suspected).
4. Passengers may connect to the spoofed network believing it is legitimate.
5. Users could be redirected to a fraudulent captive portal or phishing page (suspected).
6. Credentials or other submitted information could be harvested by the attacker.
7. Crew detects abnormal wireless behavior and disables in-flight Wi-Fi.

Note: Steps 3 through 6 are reported as suspected behavior and should not be treated as fully confirmed facts.

## Impact Assessment

=== "Integrity"

    - Rogue SSID impersonation undermines trust in in-flight network identity
    - Potential manipulation of user traffic/portal workflows can alter expected authentication paths
    - Incident response actions may require rapid operational changes during flight

=== "Confidentiality"

    - Primary risk is credential theft and phishing data exposure if passengers used rogue portals
    - Potential exposure of personal or account data entered during spoofed login flows
    - No public confirmation of compromise to aircraft operational or avionics systems

=== "Availability"

    - Immediate impact included temporary in-flight Wi-Fi service interruption
    - Defensive shutdown of passenger connectivity can affect user service continuity
    - Future incidents may trigger broader preventive service suspensions

## Mitigation Strategies

### Immediate Actions

- Disable suspicious onboard Wi-Fi service segments when rogue AP activity is detected
- Notify passengers and crew to avoid unverified SSIDs and captive portals
- Coordinate incident response with aviation regulators and law enforcement

### Short-term Measures

- Monitor for rogue APs and validate authorized SSID/BSSID mappings during flights
- Improve segmentation between passenger internet services and aircraft operational networks
- Strengthen authentication and anti-spoofing controls for captive portal workflows

### Monitoring & Detection

- Use wireless intrusion detection/prevention to flag deauth anomalies and SSID impersonation
- Log abnormal management-frame patterns and unauthorized beacon behavior
- Correlate inflight network telemetry with incident-response workflows

### Long-term Solutions

- Expand passenger awareness messaging around fake in-flight Wi-Fi risks
- Standardize rapid containment playbooks for rogue AP events in aviation environments
- Continuously test onboard wireless defenses against spoofing and phishing scenarios

## Resources and References

!!! info "Public Reporting"
    - [Delta probes Wi-Fi deauth attack on flight carrying DEF CON attendees](https://www.bleepingcomputer.com/news/security/delta-probes-wi-fi-deauth-attack-on-flight-carrying-def-con-attendees/)
    - [Unauthorized Wi-Fi network found on Delta flight after DEF CON | FOX 5 Atlanta](https://www.fox5atlanta.com/news/unauthorized-wi-fi-network-found-delta-flight-after-def-con)
    - [DEF CON dingus suspected of trying to take over Delta in-flight Wi-Fi](https://www.theregister.com/security/2026/08/11/def-con-dingus-suspected-of-trying-to-take-over-delta-in-flight-wi-fi/5286331)
    - [Delta investigates in-flight Wi-Fi spoofing on post-DEF CON flight from Las Vegas | CyberScoop](https://cyberscoop.com/delta-flight-rogue-wifi-investigation-def-con-las-vegas/)

---

*Last Updated: August 16, 2026*
