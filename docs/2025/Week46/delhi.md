# Delhi Airport GPS Spoofing Crisis
![Delhi GPS spoofing](images/delhi.png)

## Overview

A significant incident at Delhi airport involved "severe" GPS spoofing attacks in November 2025, resulting in major navigation disruptions for commercial aircraft. Fake satellite signals broadcast in the airport's airspace caused navigation systems to report inaccurate positions, undermining pilot trust and forcing widespread flight diversions, delays, and manual traffic handling.

## Technical Details

| **Attribute** | **Details** |
|---------------|-------------|
| **Incident** | Delhi Airport GPS Spoofing Crisis|
| **Vulnerability Type** | GPS Spoofing (Counterfeit Satellite Signals) |
| **Attack Vector** | Radio frequency broadcast within airport airspace |
| **Navigation Systems Impacted** | GPS, RNP-based navigation |
| **Impact Radius** | Up to 60 nautical miles from IGI |
| **Affected Stakeholders** | Pilots, ATC, Airlines, Airports, Passengers |
| **Flight Operations Impact** | 400+ flights affected, 50 min average delay |

## Attack Scenario

1. Attacker(s) transmit synchronized, strong fake GPS signals into airport airspace.
2. Aircraft on approach relying on GPS/RNP navigation receive manipulated data.
3. Pilots experience loss of positional trust; approach fixes report erroneous coordinates or altitude.
4. Aircraft must abort landings, divert, or request manual routing from ATC due to unreliable GPS.
5. Widespread operational confusion, flight delays, and emergency traffic management ensue.

### Potential Access Points

- Radio frequency intrusions near the airport
- GPS receiver vulnerability on aircraft and ground vehicles
- Precision approach operations during ground-based ILS system transitions

## Impact Assessment

=== "Safety"
    * Lost positional trust during critical approach phase
    * Risk of navigational errors or missed landings
    * Increased pilot workload and stress

=== "Operations"
    * Flight diversion and massive delays: 400+ flights, 50 minutes avg delay
    * Manual air traffic control required for re-routing and landing
    * Exceptional congestion at IGI Airport, disruption to global tracking

=== "Infrastructure Risk"
    * Threat extends beyond IGI to wider aviation reliant on GPS
    * Exposes weakness in single-system navigation trust for airports globally

## Mitigation Strategies

### :material-network-off: System Upgrades
- **ILS Upgrade**: Accelerate deployment of ground-based Instrument Landing Systems.
- **Alternate Navigation**: Reinforce policy for ground-based navaids as primary navigation during crisis.

### :material-security-network: Regulatory Measures
- **Incident Reporting**: Mandated by aviation authorities; investigation launched.
- **Tech Coordination**: Aviation and security agencies work with technical experts on radio spectrum protection.

### :material-monitor-dashboard: Detection & Response
- **Multi-channel Cross-check**: Require pilots and airlines to confirm GPS data with alternative sources.
- **NavIC GNSS Adoption**: Investment in Indian NavIC satellite system for strategic redundancy and signal verification.
- **Manual Operations**: Protocols for secure manual routing by ATC during spoofing incidents.

### :material-update: Long-term Solutions
- **Policy Change**: Ongoing regulatory reforms for airspace security.
- **Technology Investment**: Detection systems for GPS spoofing, dual-mode navigation mandates.

## Technical Recommendations

### Immediate Actions
1. **ILS Utilization**: Use ground-based Instrument Landing System for all approaches during outages.
2. **Incident Reporting**: Airlines and pilots report signal anomalies immediately.
3. **Manual Control**: Shift air traffic management to manual mode when GPS trust is lost.

### Short-term Measures
1. **Radio Frequency Monitoring**: Deploy spectrum analysis tools near major airports.
2. **Cross-check Systems**: Institutionalize the use of backup navigation sources.
3. **Public Communication**: Transparency to passengers and airlines about disruptions and response.

### Long-term Strategy
1. **GNSS Redundancy**: Widespread adoption of multi-constellation navigation systems.
2. **Detection & Policy**: Invest in active GPS spoofing detection and responsive aviation security policy.
3. **Training**: Aviation staff training on navigation threats and manual procedures.

## Resources and References

!!! info "Official & Media Reports"
    - [GPS Spoofing Crisis: How Fake Satellite Signals Are Disrupting Flights Across India - Cyber Kendra](https://www.cyberkendra.com/2025/11/gps-spoofing-crisis-how-fake-satellite.html)
    - [Delhi airport chaos: NSA Ajit Doval office to probe possible GPS spoofing, sources say - India Today](https://www.indiatoday.in/india/story/delhi-airport-chaos-nsa-ajit-dovals-office-launches-probe-into-gps-spoofing-that-disrupted-flight-ops-2816655-2025-11-10)
    - [GPS spoofing triggers chaos at Delhi's IGI Airport: How fake signals and wind shift led to flight diversions - Economic Times](https://economictimes.indiatimes.com/industry/transportation/airlines-/-aviation/gps-spoofing-triggers-chaos-at-delhis-igi-airport-how-fake-signals-and-wind-shift-led-to-flight-diversions/articleshow/125103940.cms?from=mdr)
    - [Delhi Airport Saw Major Flight Disruptions diversions Congestion This Week.](https://www.ndtv.com/india-news/delhi-airport-saw-major-flight-disruptions-diversions-congestion-this-week-here-is-why-9591027)

!!! danger "Critical Warning"
    GPS spoofing at major airports presents extreme safety risk. Trust in satellite navigation can be disrupted by attackers with moderate equipment. Immediate protocol for detection, reporting, and fallback to ground-based systems is essential.

!!! tip "Emergency Response"
    If GPS spoofing is detected:
    1. Switch to ground-based navigation immediately
    2. Report signal anomalies to relevant authorities
    3. Divert or delay flights to maintain safety
    4. Deploy RF spectrum analysis near airport and coordinate with emergency teams
    5. Communicate with affected airlines and passengers; activate manual ATC operations