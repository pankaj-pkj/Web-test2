# PHANTOM v4.0 — Web Vulnerability Scanner

● Live Scanning Web Interface (Render Deployment): https://web-testing-ybe5.onrender.com/

An autonomous, single-file web application security scanner with a live Flask UI.
It runs four phases — **OSINT/Recon → Port Scan → Spider + JS Secret Extraction →
48 Vulnerability Modules** — assigns a **CVSS v3.1** score to every finding, runs a
**false-positive verification** pass, and correlates issues into **multi-step attack
chains**. No external API keys required.

## Highlights
- **48 vulnerability detection modules** (OWASP Top 10 + modern + legacy techniques)
- **CVSS v3.1** auto-scoring with full vector strings
- **WAF fingerprinting** (15+ WAFs) and payload mutation
- **Smart Fuzzer** + recon-driven **hypothesis engine**
- **Verification layer** that flags blind/weak findings for manual review
- **Attack-chain analyzer** that narrates how findings compound into real risk

## Detection coverage (48 modules)

**Injection:** SQL Injection (error/boolean/time/UNION), SQLi via forms, NoSQL
Injection, Command Injection, LFI / `php://filter`, SSRF (cloud metadata), XXE,
XPath Injection, LDAP Injection, SSTI (multi-engine, `1337*1337` marker),
Expression Language / OGNL / SpEL injection, CRLF / HTTP response splitting,
HTTP Parameter Pollution, Prototype Pollution, Log4Shell (JNDI).

**Cross-Site & client-side:** Reflected XSS, Reflected XSS via forms, Stored XSS,
DOM-based XSS (source→sink analysis), Clickjacking, CSRF token absence,
Reverse Tabnabbing, Mixed Content.

**Auth / access control:** IDOR, Forced Browsing / access-control bypass, OAuth
misconfiguration, Open Redirect, User Enumeration, Weak/none JWT secret (HMAC
cracking), Session/cookie security, Default credentials.

**Info disclosure:** Sensitive files, Backup & source-code disclosure, Verbose
error / stack-trace leaks, Directory listing, API key / secret scanning (45+
patterns), Hidden parameter mining, Subdomain enumeration & takeover, Cloud
storage buckets (S3/GCS/Azure), Email security (SPF/DMARC), `security.txt`.

**Infra / transport / config:** Open dangerous ports & service CVEs,
Unauthenticated datastores (Redis/Mongo/Elasticsearch/Memcached), FTP anonymous
login, SSL/TLS weaknesses, Security headers, CSP/CORS analysis, Host Header
Injection, Web Cache Poisoning, Web Cache Deception, Dangerous HTTP methods /
XST (TRACE), HTTP request smuggling, Rate limiting, GraphQL introspection/DoS,
WebSocket exposure, Insecure deserialization, CMS deep scan (WordPress/Joomla/
Drupal), Unrestricted file upload, Business-logic flaws.

> Educational / authorized-testing tool. Only scan systems you own or have
> explicit permission to test.

## Run locally
```bash
pip install -r requirements.txt
python phantom.py
# open http://localhost:5000
```
