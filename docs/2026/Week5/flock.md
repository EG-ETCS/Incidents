# Shutdown of Flock Safety ALPR System in Mountain View

**Misconfiguration**{.cve-chip}  **Access Control Failure**{.cve-chip}  **Privacy Breach**{.cve-chip}

## Overview
Mountain View police shut down all Flock Safety Automatic License Plate Reader (ALPR) cameras after an audit revealed that hundreds of unauthorized law enforcement agencies were able to search the city's license-plate data—something that should have been restricted under both city policy and California law. The incident stemmed from misconfiguration and lack of proper access controls in the Flock Safety platform, allowing statewide and nationwide lookups to be enabled by default. All cameras have been disabled pending a City Council review scheduled for February 24, 2026.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **Issue Type** | Misconfiguration / Access Control Failure |
| **System** | Flock Safety ALPR (Automatic License Plate Reader) |
| **Root Cause** | Overly permissive default settings and configuration errors |
| **Affected Data** | License plate captures and associated metadata |
| **Unauthorized Access** | Hundreds of state and federal law enforcement agencies |
| **Detection Method** | Internal police department audit |

## Technical Details

The Flock Safety ALPR system uses cameras that automatically capture photos of vehicle license plates and associated metadata as vehicles pass by. However, the system was improperly configured:

### Configuration Issues
- **Statewide lookup enabled by default**: Allowed many California law enforcement agencies to search data without prior authorization
- **Nationwide lookup enabled**: For a period, out-of-state and federal agencies were able to access Mountain View's data
- **Insufficient access controls**: No proper restrictions limiting access to authorized local agencies only
- **Default permissive settings**: Settings prioritized functionality over privacy and compliance

### Affected Capabilities
- License plate image searches across state and national law enforcement networks
- Unrestricted query access to captured vehicle metadata
- No audit trail of unauthorized searches (until discovered through investigation)

## Attack Scenario

This was not a traditional cyberattack exploiting a software vulnerability. Instead, the issue stemmed from misconfiguration and governance failures:

1. Flock Safety platform was deployed with overly permissive default settings
2. Mountain View police did not properly validate configuration against city policy and state law requirements
3. "Statewide lookup" setting allowed hundreds of California law enforcement agencies to query the data
4. "Nationwide lookup" setting permitted out-of-state and federal agencies access
5. These unauthorized access routes continued undetected until a police audit revealed them
6. Upon discovery, the department immediately disabled unauthorized lookup settings
7. All ALPR cameras were shut down pending governance review

## Impact Assessment

=== "Confidentiality"
    * Exposure of vehicle license plate data to unauthorized agencies
    * Potential privacy violations of Mountain View residents
    * Unintended surveillance data sharing across jurisdictions
    * Loss of control over sensitive location tracking information

=== "Integrity"
    * Loss of data governance and access control integrity
    * Inability to ensure proper authorization chains
    * Misconfiguration of platform security settings
    * Breakdown of policy enforcement mechanisms

=== "Availability"
    * Complete suspension of ALPR capabilities for law enforcement
    * Loss of license plate tracking functionality for police operations
    * Disruption of ongoing surveillance programs
    * Pending system review may result in permanent changes or replacement

## Mitigation Strategies

### Immediate Actions
- Disable all Flock Safety ALPR cameras immediately (completed)
- Conduct comprehensive audit of all data accessed by unauthorized agencies
- Document all unauthorized searches and potential privacy violations
- Notify affected residents and civil liberties organizations
- Review all current access logs for unauthorized query patterns

### Short-term Measures
- Audit all configurations and compare against city policy requirements
- Implement strict access controls limiting to authorized local agencies only
- Implement granular role-based access control (RBAC)
- Establish audit trails for all data searches and access attempts

### Monitoring & Detection
- Monitor all future access attempts to ALPR data
- Establish automated alerts for unauthorized agency access attempts
- Track queries by jurisdiction and agency
- Review unusual search patterns and high-volume requests
- Maintain comprehensive audit logs of all system access


## Resources and References

!!! info "Incident Reports"
    - [Flock Safety ALPR Cameras Shut Down Over Data Access Issue](https://thecyberexpress.com/flock-safety-alpr-cameras-shut-down/)
    - [Mountain View police turn off Flock cameras, allege unauthorized use](https://www.sfchronicle.com/bayarea/article/mountain-view-police-flock-license-plate-readers-21330156.php)
    - [Mountain View police turn off license plate cameras after data sharing breach - Mountain View Voice](https://www.mv-voice.com/public-safety/2026/02/02/mountain-view-police-turn-off-license-plate-cameras-after-data-sharing-breach/)
