"""
PHANTOM — automated test suite (pytest).

Covers the pure logic (CVSS scoring, OWASP/CWE taxonomy, browser-header
coherence, URL de-duplication, the RL mutator, report building/rendering) plus
a few live integration tests that run real modules against a local stub server.

Run:  pytest -q
"""
import base64
import json
import threading
import time

import pytest

import phantom


# ── Pure-logic unit tests ─────────────────────────────────────────────────────
def test_cvss_known_type_is_critical():
    score, vector, sev = phantom.CVSS.score("SQL Injection")
    assert 9.0 <= score <= 10.0
    assert sev == "CRITICAL"
    assert vector.startswith("CVSS:3.1/")


def test_cvss_unknown_type_falls_back_safely():
    score, vector, sev = phantom.CVSS.score("Totally Unknown Finding")
    assert 0.0 <= score <= 10.0
    assert sev in {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


@pytest.mark.parametrize("vtype,cwe_prefix", [
    ("SQL Injection", "CWE-89"),
    ("Reflected XSS", "CWE-79"),
    ("SSRF", "CWE-918"),
    ("AI Prompt Injection", "CWE-1427"),
    ("Missing SRI", "CWE-353"),
])
def test_taxonomy_maps_cwe_and_owasp(vtype, cwe_prefix):
    cwe, owasp = phantom.taxonomy(vtype)
    assert cwe == cwe_prefix
    assert owasp.startswith("A") and ":2021" in owasp


def test_taxonomy_default_for_unknown():
    cwe, owasp = phantom.taxonomy("No Such Type")
    assert cwe and owasp  # always returns something usable


def test_realistic_headers_chrome_has_client_hints():
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0 Safari/537.36"
    h = phantom.realistic_headers(ua, referer="http://x")
    assert "sec-ch-ua" in h
    assert h["Sec-Fetch-Site"] == "same-origin"
    assert h["Referer"] == "http://x"


@pytest.mark.parametrize("ua", [
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/17.2 Safari/605.1.15",
])
def test_realistic_headers_non_chromium_omits_client_hints(ua):
    h = phantom.realistic_headers(ua)
    assert "sec-ch-ua" not in h
    assert h["Sec-Fetch-Site"] == "none"


def test_accept_encoding_never_advertises_undecodable_brotli():
    # If brotli isn't importable, "br" must not be advertised (else responses
    # come back undecodable and every text-based detector silently breaks).
    if not phantom._BROTLI_OK:
        assert "br" not in phantom.ACCEPT_ENCODING
    assert "gzip" in phantom.ACCEPT_ENCODING


def test_dedup_collapses_same_url_shape():
    urls = [
        "http://t/item?id=1", "http://t/item?id=2", "http://t/item?id=3",
        "http://t/other?q=a",
    ]
    out = phantom._dedup_urls(urls)
    # the three id=N URLs share a shape → collapsed to (far) fewer than 4
    assert len(out) < len(urls)


def test_ver_tuple_parsing_and_ordering():
    assert phantom._ver_tuple("3.3.1") < phantom._ver_tuple("3.5.0")
    assert phantom._ver_tuple("1.8") == (1, 8, 0)


def test_adaptive_mutator_warm_start_biases_known_evasions():
    m = phantom.AdaptiveMutator()
    picks = m.warm_start("Cloudflare")
    assert picks  # returns the strategies it boosted
    assert all(m.Q[p] >= 0.6 for p in picks)


def test_adaptive_mutator_apply_transforms_change_payload():
    m = phantom.AdaptiveMutator()
    _, mutated = m.mutate("<script>alert(1)</script>", strat="url_encode")
    assert "%3C" in mutated  # '<' url-encoded


# ── Report building / rendering ───────────────────────────────────────────────
def _job_with_findings():
    job = phantom.ScanJob("http://demo.example.com")
    job.add_vuln("SQL Injection", "http://demo.example.com/p?id=1", param="id",
                 payload="' OR 1=1--", evidence="SQL syntax error",
                 code="q = 'SELECT * FROM u WHERE id='+id")
    job.add_vuln("Reflected XSS", "http://demo.example.com/s?q=x", param="q",
                 payload="<script>alert(1)</script>", evidence="reflected unencoded")
    job.status = "done"
    job.elapsed = 4.2
    return job


def test_add_vuln_tags_cwe_and_owasp():
    job = _job_with_findings()
    for v in job.vulns:
        assert v["cwe"] and v["owasp"]


def test_add_vuln_dedupes_identical_evidence():
    job = phantom.ScanJob("http://x")
    job.add_vuln("SQL Injection", "http://x/a", evidence="same evidence text")
    job.add_vuln("SQL Injection", "http://x/a", evidence="same evidence text")
    assert len(job.vulns) == 1


def test_job_report_structure():
    rep = phantom.job_report(_job_with_findings())
    for key in ("scanner", "version", "target", "summary", "vulnerabilities",
                "attack_chains", "generated"):
        assert key in rep
    assert rep["summary"]["total_findings"] == 2
    json.dumps(rep, default=str)  # must be JSON-serializable


def test_html_report_is_valid_standalone():
    html = phantom.render_html_report(phantom.job_report(_job_with_findings()))
    assert html.startswith("<!DOCTYPE html>")
    assert html.rstrip().endswith("</html>")
    assert "OWASP Top 10" in html
    assert html.count('class="finding"') == 2


# ── Proof engine (reproducible, copy-paste evidence) ──────────────────────────
def test_shell_quote_roundtrips_embedded_quotes():
    import shlex
    tricky = "' OR '1'='1"
    quoted = phantom._shq(tricky)
    # the shell must parse the quoted form back to the exact original value
    assert shlex.split(quoted) == [tricky]


def test_curl_get_fills_real_params_and_replaces_injected():
    cmd = phantom._curl_get("http://t/item?id=1&cat=books", "id", "' OR 1=1--")
    assert cmd.startswith("curl -sk -G 'http://t/item'")
    assert "cat=books" in cmd          # untouched param preserved
    assert "id=" in cmd and "OR 1=1" in cmd  # injected param carries the payload


def test_proof_engine_sqli_uses_extracted_value():
    job = phantom.ScanJob("http://demo.example.com")
    job.add_vuln("SQL Injection", "http://demo.example.com/p?id=1", param="id",
                 payload="' OR '1'='1", evidence="SQL syntax error",
                 extracted={"version": "8.0.32-MySQL"})
    phantom.generate_poc(job)
    pr = job.vulns[0]["proof"]
    assert pr["command"].startswith("curl")
    assert "8.0.32-MySQL" in pr["expect"]        # the confirming value is the proof
    assert "8.0.32-MySQL" in pr["evidence"]


def test_proof_engine_xss_gives_browser_alert_url():
    job = phantom.ScanJob("http://demo.example.com")
    job.add_vuln("Reflected XSS", "http://demo.example.com/s?q=x", param="q",
                 payload="<svg onload=alert(1)>", evidence="reflected unencoded")
    phantom.generate_poc(job)
    pr = job.vulns[0]["proof"]
    assert pr["browser"].startswith("http://demo.example.com/s?")
    # canonical harmless proof payload is URL-encoded into the browser link
    assert "alert" in pr["browser"] and "document.domain" in pr["browser"]


def test_proof_pack_markdown_has_command_blocks():
    job = _job_with_findings()
    phantom.generate_poc(job)          # proofs are built during the scan flow
    md = phantom.render_proof_pack(phantom.job_report(job))
    assert md.startswith("# PHANTOM Proof Pack")
    assert "```bash" in md
    assert "**Expected result:**" in md
    assert md.count("## ") >= 2  # one section per finding


def test_proof_pack_empty_scan_is_graceful():
    job = phantom.ScanJob("http://x")
    job.status = "done"; job.elapsed = 1.0
    md = phantom.render_proof_pack(phantom.job_report(job))
    assert "nothing to reproduce" in md.lower()


def test_proof_route_via_test_client():
    job = _job_with_findings()
    phantom.generate_poc(job)
    phantom.scans[job.id] = job
    client = phantom.app.test_client()
    r = client.get(f"/proof/{job.id}.md")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("text/markdown")
    assert b"Proof Pack" in r.data
    assert client.get("/proof/does-not-exist.md").status_code == 404


# ── Live integration tests (real modules vs a local stub) ─────────────────────
@pytest.fixture(scope="module")
def stub_server():
    from flask import Flask, request, Response
    app = Flask("stub")

    @app.route("/p")
    def p():
        q = request.args.get("id", "")
        if "'" in q:
            return "<html>error in your SQL syntax near '''</html>"
        return "<html>ok</html>"

    @app.route("/api")
    def api():
        cb = request.args.get("callback", "")
        return Response(f'{cb}({{"secret":1}})', mimetype="application/javascript")

    port = 5177
    t = threading.Thread(target=lambda: app.run(port=port, threaded=True), daemon=True)
    t.start()
    time.sleep(1.0)
    return f"http://127.0.0.1:{port}"


def test_sqli_detected_live(stub_server):
    job = phantom.ScanJob(stub_server)
    phantom.mod_sqli(job, stub_server + "/p?id=1")
    assert any(v["type"] == "SQL Injection" for v in job.vulns)


def test_jsonp_detected_live(stub_server):
    job = phantom.ScanJob(stub_server)
    phantom.mod_jsonp(job, stub_server + "/api?callback=x")
    assert any(v["type"] == "JSONP Endpoint" for v in job.vulns)


def test_phase_auth_bearer_sets_header():
    job = phantom.ScanJob("http://x")
    job.auth_cfg = {"bearer": "abc123"}
    # bearer needs no network; phase_auth still probes job.url, so tolerate failure
    try:
        phantom.phase_auth(job)
    except Exception:
        pass
    assert job.auth_headers.get("Authorization") == "Bearer abc123"
    assert job.authenticated is True


def test_phase_auth_cookie_parsing():
    job = phantom.ScanJob("http://x")
    job.auth_cfg = {"cookie": "session=abc; token=xyz"}
    try:
        phantom.phase_auth(job)
    except Exception:
        pass
    assert job.auth_cookies.get("session") == "abc"
    assert job.auth_cookies.get("token") == "xyz"


@pytest.fixture(scope="module")
def api_stub():
    from flask import Flask, jsonify
    app = Flask("apistub")

    @app.route("/swagger.json")
    def spec():
        return jsonify({"openapi": "3.0.0", "info": {"title": "API"},
                        "paths": {"/api/users/{id}": {"get": {}}}})

    @app.route("/api/users/1")
    def users():
        return jsonify({"id": 1, "email": "admin@x.com", "token": "sk_live_x"})

    port = 5178
    threading.Thread(target=lambda: app.run(port=port, threaded=True), daemon=True).start()
    time.sleep(1.0)
    return f"http://127.0.0.1:{port}"


def test_openapi_discovery_and_unauth_endpoint(api_stub):
    job = phantom.ScanJob(api_stub)
    phantom.mod_openapi(job)
    types = {v["type"] for v in job.vulns}
    assert "Exposed API Documentation" in types
    assert job.api_info.get("openapi", {}).get("paths") == 1


def test_report_endpoints_via_test_client():
    job = _job_with_findings()
    phantom.scans[job.id] = job
    client = phantom.app.test_client()

    r_json = client.get(f"/report/{job.id}.json")
    assert r_json.status_code == 200
    assert r_json.headers["Content-Type"].startswith("application/json")

    r_html = client.get(f"/report/{job.id}.html")
    assert r_html.status_code == 200
    assert b"<!DOCTYPE html>" in r_html.data

    assert client.get("/report/does-not-exist.json").status_code == 404
    assert client.get("/health").status_code == 200
