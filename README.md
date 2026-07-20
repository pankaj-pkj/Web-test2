# PHANTOM v5.2 — Web Vulnerability Scanner

● Live Scanning Web Interface (Render Deployment): https://web-testing-ybe5.onrender.com/

An autonomous, single-file web application security scanner with a live Flask UI.
It runs autonomous phases — **OSINT/Recon → Port Scan → Spider + Headless DOM →
66 Vulnerability Modules** — assigns a **CVSS v3.1** score to every finding, runs a
**false-positive verification** pass, and correlates issues into **multi-step attack
chains**. **No paid API or LLM required — pure Python.**

## What's new in v5.2
- **Real-browser traffic** — every request now sends a coherent Chrome/Firefox/Safari
  fingerprint: **Client Hints** (`sec-ch-ua*`), **Fetch Metadata** (`Sec-Fetch-*`),
  a same-site `Referer`, a stable per-scan User-Agent, keep-alive **cookie reuse**
  and a little timing jitter — so passive **WAF / Cloudflare** bot checks see a
  genuine browser session instead of a bare scanner.
- **WAF-aware RL mutation** — when a WAF is fingerprinted, the reinforcement-learning
  payload mutator is **warm-started** toward the evasions that historically beat
  that WAF family (e.g. Cloudflare → case/unicode mixing; ModSecurity → comment
  breaking) before it explores on its own.
- **3 new detection modules**: **JSONP endpoint** (cross-origin data theft via
  callback), **GraphQL CSRF** (mutations accepted over GET/form-encoded), and
  **developer-comment leaks** (credentials / internal paths in HTML–JS comments).
- **Attack-chain engine expanded to 40+ correlations** — new fresh chains for
  source-map→secret pivots, SPA token theft, SSRF→cloud-metadata takeover, LFI
  log-poisoning→RCE, race-condition monetary abuse, IDOR+enumeration harvesting,
  and more.

## What's new in v5.1
- **Keep-alive connection pooling** — one reused TCP/TLS session per worker thread
  instead of a fresh handshake per request (the single biggest scan-speed win).
- **Parallel site-wide scan** — the site-wide modules now run concurrently.
- **3 new detection modules**: **Race Condition / TOCTOU**, **Client-Side Template
  Injection** (AngularJS/Vue), and **Source-Map Recovery**.

## Highlights
- **66 vulnerability detection modules** (OWASP Top 10 + modern + legacy techniques)
- **Out-of-Band (OOB) engine** — the scanner's own public URL is the interaction
  listener, so blind SSRF / RCE / XXE are *confirmed* via real call-backs (no
  third-party collaborator service needed)
- **Reinforcement-learning payload mutation** — an epsilon-greedy multi-armed
  bandit learns which mutation slips past *this* target's WAF/filters, then reuses it
- **Stateful business-logic testing** — drives multi-step flows with a live session
  to find sequence bypass, coupon replay and quantity tampering
- **API & mobile-backend fuzzing** — mass assignment, excessive data exposure,
  method-override smuggling, broken object/function-level access
- **Headless browser (Playwright)** — renders SPAs in real Chromium for dynamic
  DOM-XSS confirmation and client-side route discovery (degrades gracefully)
- **Speed-first**: keep-alive connection pooling, parallel site-wide scan,
  URL-shape de-duplication, 24 worker threads, time budget — a typical scan
  finishes in well under a minute
- **CVSS v3.1** auto-scoring, **WAF fingerprinting** (15+ WAFs), recon-driven
  **hypothesis engine**, a **verification layer** for false-positive reduction,
  and an **attack-chain analyzer** that shows how findings compound

## Analyst workflow (5 reasoning stages)
1. **Form Hypotheses** — recon-driven hypothesis engine *and* a static code-pattern
   review of the site's own HTML/JS (innerHTML, eval, hard-coded keys, http:// …).
2. **Test & Verify** — every finding is confidence-scored from its evidence; blind/
   weak results are flagged for manual review (false-positive reduction).
3. **Chain Attacks** — correlates findings into multi-step attack paths and shows
   the escalated, combined impact.
4. **Generate Exploits (PoC)** — produces a safe, reproduction-only Proof-of-Concept
   (the exact request/payload that demonstrated the issue) plus CVE references, for
   verification and remediation.
5. **Reverse Engineer** — static analysis of shipped artifacts (JS bundles, source
   maps, wasm, apk, jar, exe…): string/secret extraction and dangerous-call detection.

Every finding now also shows **WHERE IN CODE** — the exact source line/snippet that
contains the issue — so you can see *what* is wrong and *where* to fix it.

### Configuration (environment variables)
| Var | Default | Purpose |
|-----|---------|---------|
| `OOB_URL` / `RENDER_EXTERNAL_URL` | (Render sets it) | Public base for the OOB listener |
| `PHANTOM_FAST` | `1` | Speed-first mode |
| `PHANTOM_BUDGET` | `300` | Hard per-scan time budget (seconds) |
| `PHANTOM_THREADS` | `24` | Concurrent workers |

## Detection coverage (66 modules)

**Injection:** SQL Injection (error/boolean/time/UNION), SQLi via forms, NoSQL
Injection, Command Injection, LFI / `php://filter`, SSRF (cloud metadata), XXE,
XPath Injection, LDAP Injection, SSTI (multi-engine, `1337*1337` marker),
Expression Language / OGNL / SpEL injection, CRLF / HTTP response splitting,
HTTP Parameter Pollution, Prototype Pollution, Log4Shell (JNDI).

**Cross-Site & client-side:** Reflected XSS, Reflected XSS via forms, Stored XSS,
DOM-based XSS (source→sink analysis), Client-Side Template Injection (Angular/Vue),
Clickjacking, CSRF token absence, Reverse Tabnabbing, Mixed Content.

**Business logic & timing:** Race Condition / TOCTOU (parallel-request limit
bypass), business-logic flaws (negative/zero/overflow values), stateful
multi-step sequence abuse, coupon replay and quantity tampering.

**Auth / access control:** IDOR, Forced Browsing / access-control bypass, OAuth
misconfiguration, Open Redirect, User Enumeration, Weak/none JWT secret (HMAC
cracking), Session/cookie security, Default credentials.

**Info disclosure:** Sensitive files, Backup & source-code disclosure, JavaScript
source-map recovery (original pre-minified source via `sourcesContent`),
developer-comment leaks (credentials / internal paths in HTML–JS comments),
Verbose error / stack-trace leaks, Directory listing, API key / secret scanning
(45+ patterns), Hidden parameter mining, Subdomain enumeration & takeover, Cloud
storage buckets (S3/GCS/Azure), Email security (SPF/DMARC), `security.txt`.

**APIs & cross-origin:** GraphQL introspection / DoS / batching, **GraphQL CSRF**
(GET/form-encoded mutations), **JSONP** cross-origin data theft, CORS
misconfiguration, mass assignment, excessive data exposure, HTTP method override.

**Infra / transport / config:** Open dangerous ports & service CVEs,
Unauthenticated datastores (Redis/Mongo/Elasticsearch/Memcached), FTP anonymous
login, SSL/TLS weaknesses, Security headers, CSP/CORS analysis, Host Header
Injection, Web Cache Poisoning, Web Cache Deception, Dangerous HTTP methods /
XST (TRACE), HTTP request smuggling, Rate limiting, WebSocket exposure, Insecure
deserialization, CMS deep scan (WordPress/Joomla/Drupal), Unrestricted file
upload, Business-logic flaws.

### Evasion & realism (authorized testing)
Requests carry a coherent real-browser fingerprint (Client Hints + Fetch Metadata
+ same-site Referer + stable UA + cookie reuse) and the RL payload mutator is
warm-started with WAF-specific evasions once a WAF is fingerprinted, so the scanner
behaves like a genuine browser session against passive WAF/Cloudflare checks. This
is standard authorized-pentest tradecraft (as in sqlmap/Burp/ZAP) — use it only on
systems you own or are permitted to test.

> Educational / authorized-testing tool. Only scan systems you own or have
> explicit permission to test.

## Run locally
```bash
pip install -r requirements.txt
python phantom.py
# open http://localhost:5000
```
