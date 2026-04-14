# Implementation Plan: Advanced RPC Payload Dictionary & Bypass Guide

The objective is to produce a high-fidelity dictionary of "Advanced" payloads for use in Burp Suite Intruder. These payloads will be specifically engineered to bypass modern Web Application Firewalls (WAFs), Content Security Policies (CSP), and standard RPC input filters.

## User Review Required

> [!IMPORTANT]
> **To optimize the "Advanced" selection, please provide context on:**
> - **CSP Details**: What is the current `script-src` directive? (e.g., is there a specific whitelisted domain or 'unsafe-inline'?).
> - **WAF Behavior**: Have you noticed specific characters being blocked (e.g., `< `, `(`, `single quotes`) that trigger the 400 error?

## Proposed Changes

### [Vulnerability Deep-Dive Document]

#### [NEW] [advanced_rpc_payload_dictionary.md](file:///c:/Users/gayat/.gemini/antigravity/brain/46ff7cbf-42f2-4c0a-8a23-06f347884787/advanced_rpc_payload_dictionary.md)

1.  **Advanced XSS (CSP/WAF Bypass)**:
    - Focus on **Script Gadgets** (exploiting whitelisted framework code).
    - **Polyglot payloads** that survive different parsing contexts.
    - **Non-alpha/numeric** payloads for bypassing regex filters.
2.  **Advanced XXE (OOB and Error-Based)**:
    - **Parameter Entity** nesting to bypass WAF XML inspection.
    - **Billion Laughs** variants for localized DoS.
3.  **Advanced SSRF (Metadata and Cloud Bypass)**:
    - IP address obfuscation (Hex, Octal, Decimal representations).
    - DNS Rebinding templates.
4.  **Advanced Command Injection (WAF Evasion)**:
    - Space-less payloads using `${IFS}` or `$IFS$9`.
    - Obfuscated keywords using `\` or `${a:-}` expansion.
    - Termination characters (Line feed `%0a`, vertical tab).
5.  **Burp Intruder Raw List**:
    - A consolidated text block for direct copy-pasting into Intruder.

## Verification Plan

### Manual Verification
- Review the payloads to ensure they follow correctly formatted JSON/XML RPC structures.
- Verify that the bypass techniques align with current (2024-2025) security research.
