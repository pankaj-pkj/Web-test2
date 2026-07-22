# PHANTOM v5.3 — Web Vulnerability Scanner

![CI](https://github.com/pankaj-pkj/web-test2/actions/workflows/ci.yml/badge.svg)

● Live Scanning Web Interface (Render Deployment): https://web-testing-ybe5.onrender.com/

An autonomous, single-file web application security scanner with a live Flask UI.
It runs autonomous phases — **OSINT/Recon → Port Scan → Spider + Headless DOM →
71 Vulnerability Modules** — assigns a **CVSS v3.1** score to every finding, runs a
**false-positive verification** pass, and correlates issues into **multi-step attack
chains**. **No paid API or LLM required — pure Python.**

## What's new in v5.3
- **Professional HTML report** — executive summary, risk rating, severity chart,
  **OWASP Top 10 (2021)** breakdown and per-finding **CWE + OWASP + CVSS** with the
  vulnerable-code snippet, remediation and PoC. Self-contained → Ctrl-P for a PDF.
  Buttons in the UI, `GET /report/<id>.html`, and `--html` in the CLI.
- **5 modern modules**: vulnerable-JS-library detection, missing **SRI**,
  **AI/LLM prompt-injection** probe, insecure **postMessage**, and deep **JWT**
  analysis — bringing the total to **71**.

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
- **71 vulnerability detection modules** (OWASP Top 10 + modern + legacy techniques)
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

## Detection coverage (71 modules)

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

**Supply-chain, client-side & AI (modern):** vulnerable front-end library
detection (retire.js-style — jQuery/Angular/Bootstrap/Lodash/Moment/Handlebars),
missing **Subresource Integrity (SRI)** on third-party scripts, **AI/LLM prompt
injection** probe (benign canary, OWASP LLM01), insecure **postMessage** handlers
(no origin check), and deep **JWT** analysis (alg:none, missing expiry, sensitive
claims).

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

## Run locally (web UI)
```bash
pip install -r requirements.txt
python phantom.py
# open http://localhost:5000
```

## Tests & CI
An automated **pytest** suite covers the scoring/taxonomy logic, browser-header
coherence, report building/rendering and live detection modules (against a local
stub). **GitHub Actions** runs it on every push across Python 3.10–3.12.
```bash
pip install -r requirements-dev.txt
pytest -q
```

## Run in Termux / any terminal (headless → JSON file)
No browser needed — the scanner runs the full engine from the command line and
writes a structured JSON report. Ideal for Android (Termux) or when the web app
can't run in your environment.

```bash
# one-time setup in Termux
pkg install python git -y
git clone <this-repo> && cd Web-test2
pip install -r requirements.txt

# scan and save a JSON report
python phantom.py https://your-authorized-target.com
python phantom.py https://target.com -o report.json   # choose the output file
python phantom.py https://target.com --quiet           # only the final summary
python phantom.py https://target.com --print           # also echo the JSON
python phantom.py --help                                # usage
```
The report file (`phantom_<host>_<id>.json`) contains a `summary` (risk + counts),
every `vulnerabilities` entry (with CVSS score/vector, evidence, the exact
vulnerable `code` snippet, remediation `fix` and a reproduction `poc`), the
correlated `attack_chains`, discovered ports/subdomains/secrets and the run log.

## Reports (JSON + professional HTML)
Every scan produces both a machine-readable JSON report and a polished,
self-contained **HTML report** (executive summary, risk rating, severity chart,
**OWASP Top 10 (2021)** breakdown, and per-finding **CWE + OWASP + CVSS**,
vulnerable-code snippet, remediation and PoC). The HTML is standalone — open it
in any browser and **Ctrl-P → Save as PDF** for a submission-ready document.

- **In the UI**: the results page has **📄 HTML Report**, **⬇ Download JSON Report**
  and **⧉ Open JSON (API)** buttons.
- **Direct URLs**: `GET /report/<scan_id>.html` (viewable report) and
  `GET /report/<scan_id>.json` (structured download). `POST /scan` (form field
  `url`) starts a scan and returns `{"scan_id": ...}`; poll
  `GET /api/status/<scan_id>` for progress.
- **CLI**: add `--html` to also write the HTML report next to the JSON file.
