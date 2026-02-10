# Google Protocol Buffers JSON Parsing Denial-of-Service Vulnerability
![alt text](images/protobuf.png)

**CVE-2026-0994**{.cve-chip} **Denial-of-Service**{.cve-chip} **JSON Parsing**{.cve-chip}

## Overview
CVE-2026-0994 is a high-severity vulnerability in Google Protocol Buffers (protobuf) affecting the Python implementation. The flaw allows an attacker to crash an application by sending a specially crafted JSON payload. By abusing deeply nested protobuf Any message types, the attacker can bypass built-in recursion limits, leading to uncontrolled recursion and service termination.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **CVE ID** | CVE-2026-0994 |
| **Vulnerability Type** | Denial-of-Service (DoS) via Recursion Bypass |
| **CVSS Score**| 8.2 (High) |
| **Attack Vector** | Network |
| **Authentication** | None |
| **Complexity** | Low |
| **User Interaction** | Not Required |
| **Affected Component** | google.protobuf.json_format.ParseDict() |

## Affected Products
- Python protobuf library (google-protobuf package)
- Any application using Python protobuf for JSON parsing
- Status: Active / Patch Available

## Technical Details

The vulnerability exists in `google.protobuf.json_format.ParseDict()`. While the function enforces a recursion depth limit, nested `google.protobuf.Any` messages are processed by `_ConvertAnyMessage()`, which does not increment or decrement the recursion counter. This results in:

- Infinite or very deep recursion bypassing the limit
- Python stack exhaustion
- Application crash (RecursionError)

## Attack Scenario
1. Attacker identifies an API or service that parses untrusted JSON input using Python protobuf
2. Attacker crafts a JSON payload containing deeply nested Any protobuf objects
3. The recursion limit is bypassed through the helper function
4. The service crashes due to stack overflow (RecursionError)
5. Repeated requests can keep the service offline (persistent DoS)

## Impact Assessment

=== "Availability"
    * Service or API crashes
    * Application unavailability
    * Potential repeated outages
    * Can be exploited remotely and unauthenticated

=== "Confidentiality"
    * No direct data theft impact
    * Indirect exposure through service disruption

=== "Integrity"
    * No direct data corruption
    * Indirect impacts through denial of service

## Mitigation Strategies

### Immediate Actions
- Update to patched versions of the Python protobuf library immediately
- Review applications using Python protobuf for JSON parsing
- Monitor for exploitation attempts in application logs

### Short-term Measures
- Implement input size limits for JSON payloads
- Add JSON depth validation before parsing
- Use defensive error handling around protobuf parsing calls
- Consider temporarily disabling untrusted JSON parsing if possible

### Monitoring & Detection
- Monitor vendor advisories and Linux distribution security updates
- Track RecursionError exceptions in application logs
- Monitor for repeated failed JSON parsing attempts
- Alert on unusual API response times or crashes

## Resources and References

!!! info "Incident Reports"
    - [High-Severity DoS Flaw Hits Google Protocol Buffers (CVE-2026-0994)](https://securityonline.info/high-severity-dos-flaw-hits-google-protocol-buffers-cve-2026-0994/)
    - [NVD - CVE-2026-0994](https://nvd.nist.gov/vuln/detail/cve-2026-0994)
    - [Ubuntu Security Advisory - CVE-2026-0994](https://ubuntu.com/security/CVE-2026-0994)
    - [CVE-2026-0994 : A denial-of-service (DoS) vulnerability exists in google.protobuf.json_format.Pa](https://www.cvedetails.com/cve/CVE-2026-0994/)
