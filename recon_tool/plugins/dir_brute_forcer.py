# recon_tool/plugins/dir_brute_forcer.py

"""
dir_brute_forcer.py (enhanced)
------------------------------

Hybrid content discovery for better SQLi/LFI coverage:

- Uses ports.json to build base URLs (http/https).
- Bruteforces paths from a wordlist (+ optional extensions).
- Lightweight BFS crawl (same-host) with per-host caps.
- Pulls robots.txt and sitemap.xml to seed more URLs.
- Extracts forms (action/method/inputs) and visible links.
- Harvests endpoints from inline/external JS (fetch/XHR/url-like strings).
- Calibrates soft-404 to avoid false positives.
- Scores login pages and looks for DB error strings.
- Exports rich artifacts for downstream plugins:
    web/paths.json, web/login_candidates.json, web/forms.json,
    web/endpoints.json, web/js_endpoints.json, web/seed_pages.json

NOTE: Intentionally does NOT include virtual-host fuzzing (per user request).
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse, urlencode, parse_qsl

import aiohttp
from bs4 import BeautifulSoup  # type: ignore

from recon_tool.core import BasePlugin, ScanContext


# ------------------------
# Tunables (safe defaults)
# ------------------------

MAX_CONCURRENCY = 20
HTTP_TIMEOUT = 10
CRAWL_MAX_PAGES = 250        # hard stop per host
CRAWL_MAX_DEPTH = 3
JS_FETCH_MAX = 60            # limit external JS fetches
WORDLIST_FALLBACK = "/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt"

COMMON_EXTENSIONS = ["", "/", ".php", ".asp", ".aspx", ".jsp", ".html", ".txt", ".bak"]
PRIORITY_SLUGS = [
    "", "/", "index.php", "index.html", "home",
    "login", "signin", "register", "signup", "forgot", "reset",
    "admin", "administrator", "dashboard",
    "user", "users", "profile", "account", "settings",
    "post", "posts", "article", "news", "product", "items",
    "search", "query",
    "flag", "secret", "debug", "config", "backup", "db", "sql",
    "api", "api/v1", "api/v2", "graphql",
    "terms", "terms-and-conditions", "privacy", "contact", "help",
]

# Heuristics for parameters useful to SQLi/LFI
SQLIISH_PARAMS = [
    "id", "post_id", "user_id", "uid", "pid", "page", "p", "cat", "category",
    "q", "query", "search", "sort", "order", "type", "year", "month", "limit", "offset",
]
LFIISH_PARAMS = [
    "file", "filepath", "path", "include", "inc", "page", "view", "template",
    "dir", "directory", "folder", "resource", "name", "locale",
]

DB_ERROR_PATTERNS = [
    re.compile(r"SQL syntax.*?MySQL", re.I),
    re.compile(r"mysql_fetch_array", re.I),
    re.compile(r"PostgreSQL.*?ERROR", re.I),
    re.compile(r"SQLSTATE\[", re.I),
    re.compile(r"Unclosed quotation mark after the character string", re.I),  # MSSQL
    re.compile(r"ORA-\d{5}", re.I),  # Oracle
]

LOGIN_URL_PATTERNS = [re.compile(r"/login\b", re.I), re.compile(r"/admin\b", re.I)]
LOGIN_KEYWORDS = ["login", "sign in", "username", "password", "register"]


@dataclass
class Soft404Model:
    status: int
    length: int
    token: Optional[str] = None


class DirBruteForcerPlugin(BasePlugin):
    name = "DirBruteForcer"
    description = "Discover web files/directories and identify entry points"
    priority = 30

    def __init__(self, context: ScanContext) -> None:
        super().__init__(context)
        self.concurrency = MAX_CONCURRENCY
        self.patterns: List[Tuple[re.Pattern, str, int]] = []  # (regex, label, severity)
        self.pattern_matches: List[Dict[str, Any]] = []

        # WAF detection counters
        self._waf_block_count: int = 0
        self._waf_total_requests: int = 0
        self._waf_threshold: float = 0.1

        # Soft 404 per-base cache
        self.soft404: Dict[str, Soft404Model] = {}

        # Storage (per target run)
        self.paths_result: List[Dict[str, Any]] = []
        self.login_candidates: List[Dict[str, Any]] = []
        self.forms: List[Dict[str, Any]] = []
        self.endpoints: Dict[str, Dict[str, Any]] = {}  # url -> {params:set, path_params:set, flags:{}}
        self.js_endpoints: Set[str] = set()
        self.seed_pages: Set[str] = set()

    # ----------------
    # Setup / helpers
    # ----------------

    async def setup(self) -> None:
        # Ensure BeautifulSoup is available (installed via requirements)
        try:
            import bs4  # noqa: F401
        except ImportError:
            raise RuntimeError("beautifulsoup4 is missing. pip install beautifulsoup4")

        # Wordlist presence if provided
        if self.context.wordlist and not os.path.isfile(self.context.wordlist):
            raise FileNotFoundError(f"Wordlist not found: {self.context.wordlist}")

        # Load optional regex patterns (TOML)
        patterns_file = self.context.patterns_file
        if patterns_file:
            try:
                import toml  # type: ignore
                data = toml.load(patterns_file)
                entries = data.get("patterns", [])
                for entry in entries:
                    regex = entry.get("regex")
                    label = entry.get("label", "")
                    severity = int(entry.get("severity", 1))
                    if regex:
                        compiled = re.compile(regex, re.I)
                        self.patterns.append((compiled, label, severity))
                if self.patterns:
                    self.log(
                        f"Loaded {len(self.patterns)} pattern definitions from {patterns_file}",
                        Path(self.context.results_dir),
                        level="DEBUG",
                    )
            except Exception as exc:
                self.log(
                    f"Failed to load pattern definitions from {patterns_file}: {exc}",
                    Path(self.context.results_dir),
                    level="WARN",
                )

    # ----------------
    # Main entry point
    # ----------------

    async def scan_target(self, target: str, out_dir: Path) -> None:
        ports_file = out_dir / "ports.json"
        http_ports = set()
        if ports_file.exists():
            with open(ports_file, "r", encoding="utf-8") as f:
                pdata = json.load(f)
            for entry in pdata.get("ports", []):
                if entry.get("service") in ("http", "https", "http-proxy", "ssl/http"):
                    http_ports.add(entry.get("port"))

        if not http_ports:
            self.log(f"No HTTP/HTTPS ports on {target}, skipping", out_dir, level="DEBUG")
            return

        base_urls = []
        for port in sorted(http_ports):
            scheme = "https" if port == 443 else "http"
            if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
                base_urls.append(f"{scheme}://{target}:{port}")
            else:
                base_urls.append(f"{scheme}://{target}")

        # concurrency / WAF adjustment
        if self.context.additional_options.get("waf_detected"):
            self.concurrency = max(6, self.concurrency // 2)

        # Build bruteforce list
        wordlist_path = self.context.wordlist or WORDLIST_FALLBACK
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [w.strip() for w in f if w.strip() and not w.startswith("#")]
        except Exception as exc:
            self.log(f"Error reading wordlist {wordlist_path}: {exc}", out_dir, level="ERROR")
            return

        # Add priority slugs at the front
        words = list(dict.fromkeys(PRIORITY_SLUGS + words))

        # Fetch session
        sem = asyncio.Semaphore(self.concurrency)
        timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT + 5)
        headers_pool = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/122.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        ]

        async with aiohttp.ClientSession(timeout=timeout) as session:
            for base in base_urls:
                # Calibrate soft-404 model for this base
                await self._calibrate_soft_404(session, base, sem)

                # Seed from robots/sitemap
                robots_urls, sitemap_urls = await self._pull_metafiles(session, base, sem)
                for u in robots_urls | sitemap_urls:
                    self._enqueue_seed(u)

                # Run a bounded crawl (BFS) starting from base
                await self._bounded_crawl(session, base, sem)

                # Bruteforce pass (with extensions)
                tasks: List[asyncio.Task] = []
                for word in words:
                    for ext in COMMON_EXTENSIONS:
                        rel = f"{word}{ext}".lstrip("/")
                        url = f"{base}/{rel}"
                        tasks.append(asyncio.create_task(self._fetch_and_analyze(url, session, sem, random.choice(headers_pool))))
                        if len(tasks) >= self.concurrency * 8:
                            await asyncio.gather(*tasks)
                            tasks = []
                if tasks:
                    await asyncio.gather(*tasks)

        # Write outputs
        web_dir = out_dir / "web"
        web_dir.mkdir(parents=True, exist_ok=True)

        with open(web_dir / "paths.json", "w", encoding="utf-8") as f:
            json.dump(self.paths_result, f, indent=2)

        with open(web_dir / "login_candidates.json", "w", encoding="utf-8") as f:
            json.dump(self.login_candidates, f, indent=2)

        with open(web_dir / "forms.json", "w", encoding="utf-8") as f:
            json.dump(self.forms, f, indent=2)

        # Normalize endpoints dict → list
        endpoints_list = []
        for url, meta in sorted(self.endpoints.items()):
            endpoints_list.append({
                "url": url,
                "params": sorted(list(meta.get("params", set()))),
                "path_params": sorted(list(meta.get("path_params", set()))),
                "flags": meta.get("flags", {}),
            })
        with open(web_dir / "endpoints.json", "w", encoding="utf-8") as f:
            json.dump(endpoints_list, f, indent=2)

        with open(web_dir / "js_endpoints.json", "w", encoding="utf-8") as f:
            json.dump(sorted(list(self.js_endpoints)), f, indent=2)

        with open(web_dir / "seed_pages.json", "w", encoding="utf-8") as f:
            json.dump(sorted(list(self.seed_pages)), f, indent=2)

        # WAF heuristic flag
        if self._waf_total_requests > 0 and (self._waf_block_count / self._waf_total_requests) >= self._waf_threshold:
            self.context.additional_options["waf_detected"] = True
            self.log(
                f"Potential WAF detected: {self._waf_block_count}/{self._waf_total_requests} blocked",
                out_dir,
                level="WARN",
            )

        self.log(f"Completed directory/crawl on {target}: {len(self.paths_result)} interesting paths", out_dir)

    # --------------------------
    # Discovery & analysis core
    # --------------------------

    def _enqueue_seed(self, url: str) -> None:
        # Collect prioritized pages for downstream modules (header/cookie, etc.)
        self.seed_pages.add(url)

    async def _calibrate_soft_404(self, session: aiohttp.ClientSession, base: str, sem: asyncio.Semaphore) -> None:
        # Request a random definitely-not-existing path; record status/length/token
        rnd = f"/{int(time.time())}-{random.randint(100000,999999)}-does-not-exist"
        url = f"{base}{rnd}"

        async with sem:
            try:
                async with session.get(url, allow_redirects=True) as resp:
                    text = await resp.text(errors="ignore")
                    model = Soft404Model(status=resp.status, length=len(text))
                    # crude token: detect "not found" strings
                    m = re.search(r"(not\s+found|doesn[’']t exist|404)", text, re.I)
                    if m:
                        model.token = m.group(1).lower()
                    self.soft404[base] = model
            except Exception:
                # Default: unknown
                self.soft404[base] = Soft404Model(status=404, length=0, token=None)

    def _is_soft_404(self, base: str, status: int, body: str) -> bool:
        model = self.soft404.get(base)
        if not model:
            return False
        # If server returns 200 with similar length or obvious "not found"
        if status == 200:
            if abs(len(body) - model.length) <= max(120, int(0.1 * max(1, model.length))):
                return True
            if model.token and re.search(re.escape(model.token), body, re.I):
                return True
        return False

    async def _pull_metafiles(self, session: aiohttp.ClientSession, base: str, sem: asyncio.Semaphore) -> Tuple[Set[str], Set[str]]:
        robots_urls, sitemap_urls = set(), set()

        async def get_text(u: str) -> Optional[str]:
            async with sem:
                try:
                    async with session.get(u, allow_redirects=True, timeout=HTTP_TIMEOUT) as resp:
                        if resp.status < 400 and "text" in (resp.headers.get("Content-Type","")):
                            return await resp.text(errors="ignore")
                except Exception:
                    return None
            return None

        # robots.txt
        robots_txt = await get_text(f"{base}/robots.txt")
        if robots_txt:
            for m in re.finditer(r"(?im)^\s*Allow:\s*(\S+)", robots_txt):
                robots_urls.add(urljoin(base + "/", m.group(1)))
            for m in re.finditer(r"(?im)^\s*Disallow:\s*(\S+)", robots_txt):
                # Disallow entries still useful to *discover* hidden paths
                robots_urls.add(urljoin(base + "/", m.group(1)))
            for m in re.finditer(r"(?im)^\s*Sitemap:\s*(\S+)", robots_txt):
                sitemap_urls.add(m.group(1))

        # sitemap(s)
        async def parse_sitemap_xml(xml: str) -> Set[str]:
            urls: Set[str] = set()
            # really simple URL extraction
            for m in re.finditer(r"<loc>(.*?)</loc>", xml, re.I | re.S):
                loc = m.group(1).strip()
                if loc.startswith("http"):
                    urls.add(loc)
            return urls

        newmaps: Set[str] = set()
        for sm in set(sitemap_urls):
            txt = await get_text(sm)
            if txt:
                urls = await parse_sitemap_xml(txt)
                newmaps |= urls

        # Convert robots_urls to absolute
        robots_abs = {urljoin(base + "/", u) for u in robots_urls if u}
        for u in robots_abs | newmaps:
            self._enqueue_seed(u)

        return robots_abs, newmaps

    async def _bounded_crawl(self, session: aiohttp.ClientSession, base: str, sem: asyncio.Semaphore) -> None:
        """
        Lightweight BFS crawl within same scheme/host/port. Depth-limited.
        """
        parsed_base = urlparse(base)
        q: List[Tuple[str,int]] = [(base, 0)]
        seen: Set[str] = set()

        while q and len(seen) < CRAWL_MAX_PAGES:
            url, depth = q.pop(0)
            if url in seen or depth > CRAWL_MAX_DEPTH:
                continue
            seen.add(url)

            await self._fetch_and_analyze(url, session, sem)

            # Only parse links/forms on HTML pages in same origin
            html = self._last_html if getattr(self, "_last_url", None) == url else None
            if not html:
                continue

            # Extract forms
            self._extract_forms(url, html)

            # Extract links
            for link in self._extract_links(url, html):
                p = urlparse(link)
                if p.scheme == parsed_base.scheme and p.netloc == parsed_base.netloc:
                    if link not in seen:
                        q.append((link, depth + 1))

            # Extract JS endpoints (inline) and fetch some external JS
            inl, externals = self._extract_js(url, html)
            self.js_endpoints |= inl
            for jsu in list(externals)[:JS_FETCH_MAX]:
                await self._fetch_js_and_extract(jsu, session, sem)

    async def _fetch_js_and_extract(self, url: str, session: aiohttp.ClientSession, sem: asyncio.Semaphore) -> None:
        async with sem:
            try:
                async with session.get(url, allow_redirects=True, timeout=HTTP_TIMEOUT) as resp:
                    if resp.status < 400 and "javascript" in resp.headers.get("Content-Type",""):
                        text = await resp.text(errors="ignore")
                        found, _ = self._extract_js(url, text, external=True)
                        self.js_endpoints |= found
            except Exception:
                return

    async def _fetch_and_analyze(self, url: str, session: aiohttp.ClientSession, sem: asyncio.Semaphore, ua: Optional[str] = None) -> None:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        headers = {"User-Agent": ua} if ua else None

        async with sem:
            try:
                async with session.get(url, allow_redirects=True, timeout=HTTP_TIMEOUT, headers=headers) as resp:
                    text = await resp.text(errors="ignore")
                    self._last_url = str(resp.url)
                    self._last_html = text if "text/html" in resp.headers.get("Content-Type","") else None

                    # WAF counters
                    self._waf_total_requests += 1
                    if resp.status in (403, 429, 503) or re.search(r"(forbidden|access denied|blocked)", text, re.I):
                        self._waf_block_count += 1

                    # Soft 404 heuristic
                    soft = self._is_soft_404(base, resp.status, text)

                    # Record interesting (non-obvious 404s or soft-404 flagged separately)
                    if resp.status < 400 or soft:
                        self._record_path(str(resp.url), resp.status, len(text), resp.headers.get("Content-Type",""), soft)

                    # Login scoring
                    score, hints, db_errs = self._score_login_page(str(resp.url), text)
                    if score >= 5:
                        self.login_candidates.append({
                            "url": str(resp.url),
                            "score": score,
                            "hints": hints,
                            "db_errors": db_errs,
                        })

                    # Pattern scanning (optional)
                    if self.patterns:
                        self._scan_patterns(str(resp.url), text)

                    # Harvest params from this URL
                    self._harvest_endpoint(str(resp.url))
            except Exception:
                return

    def _record_path(self, url: str, status: int, length: int, ctype: str, soft_404: bool) -> None:
        self.paths_result.append({
            "url": url,
            "status": status,
            "length": length,
            "content_type": ctype,
            "soft_404": bool(soft_404),
        })
        # Seeds for header/cookie tests: add canonical pages
        if any(seg in url.lower() for seg in ["/login", "/register", "/user", "/profile", "/post", "/flag", "/terms", "/privacy", "/contact", "/search", "/api"]):
            self._enqueue_seed(url)

    # --------------------------
    # Extraction & normalization
    # --------------------------

    def _extract_links(self, base_url: str, html: str) -> Set[str]:
        links: Set[str] = set()
        try:
            soup = BeautifulSoup(html, "html.parser")
            # anchor and areas
            for tag in soup.find_all(["a", "area"]):
                href = (tag.get("href") or "").strip()
                if not href or href.startswith(("javascript:", "mailto:", "#")):
                    continue
                links.add(urljoin(base_url, href))
            # also simple forms' action locations (GET/POST endpoints)
            for form in soup.find_all("form"):
                action = (form.get("action") or "").strip()
                if action:
                    links.add(urljoin(base_url, action))
        except Exception:
            pass
        return links

    def _extract_forms(self, page_url: str, html: str) -> None:
        try:
            soup = BeautifulSoup(html, "html.parser")
            for form in soup.find_all("form"):
                action = urljoin(page_url, (form.get("action") or "").strip() or page_url)
                method = (form.get("method") or "GET").upper()
                inputs = []
                for inp in form.find_all(["input", "select", "textarea"]):
                    name = inp.get("name")
                    itype = (inp.get("type") or ("textarea" if inp.name == "textarea" else "text")).lower()
                    if name:
                        inputs.append({"name": name, "type": itype})
                self.forms.append({"page": page_url, "action": action, "method": method, "inputs": inputs})
                # Enrich endpoints with form action & field names
                self._harvest_endpoint(action, extra_params=[i["name"] for i in inputs if "name" in i])
                # Add obvious seeds
                if any(k in (action.lower()) for k in ("/login", "/register", "/user", "/profile")):
                    self._enqueue_seed(action)
        except Exception:
            return

    def _extract_js(self, page_or_js_url: str, text: str, external: bool = False) -> Tuple[Set[str], Set[str]]:
        """
        Extract likely endpoints from JS (inline & external) and list of external JS URLs to fetch.
        """
        found: Set[str] = set()
        externals: Set[str] = set()

        # External scripts
        if not external and "<script" in text:
            try:
                soup = BeautifulSoup(text, "html.parser")
                for s in soup.find_all("script"):
                    src = (s.get("src") or "").strip()
                    if src:
                        externals.add(urljoin(page_or_js_url, src))
            except Exception:
                pass

        blob = text

        # fetch/axios/XMLHttpRequest patterns
        for m in re.finditer(r"""\b(?:fetch|axios\.(?:get|post|put|delete)|XMLHttpRequest\s*\()\s*[\(\s'"]([^'")\s]+)""", blob, re.I):
            u = m.group(1)
            if u.startswith(("http://", "https://", "/")):
                found.add(urljoin(page_or_js_url, u))

        # Simple URL-looking strings (api paths, .php endpoints)
        for m in re.finditer(r"""['"](/?(?:api/[^'"]+|[a-z0-9_\-\/]+\.php(?:\?[^'"]*)?))['"]""", blob, re.I):
            found.add(urljoin(page_or_js_url, m.group(1)))

        # Generic id=, page=, file= patterns inside strings
        for m in re.finditer(r"""['"](/[^'"]+\?(?:[^'"]*?(?:id|page|file|path|include)=[^'"]+))['"]""", blob, re.I):
            found.add(urljoin(page_or_js_url, m.group(1)))

        # Record endpoints
        for u in found:
            self._harvest_endpoint(u)
        return found, externals

    def _harvest_endpoint(self, url: str, extra_params: Optional[List[str]] = None) -> None:
        """
        Normalize an endpoint entry (query param names + path parameter hints + flags).
        """
        try:
            p = urlparse(url)
        except Exception:
            return
        if not p.scheme or not p.netloc:
            return

        key = urlunparse((p.scheme, p.netloc, p.path, "", "", ""))  # strip query/frag
        meta = self.endpoints.setdefault(key, {"params": set(), "path_params": set(), "flags": {}})

        # Query params
        params = {k for (k, _v) in parse_qsl(p.query, keep_blank_values=True)}
        if extra_params:
            params |= set(extra_params)
        if params:
            meta["params"] |= set(params)

        # Path parameter hint (e.g., /post/123 → {id})
        # Simple heuristic: trailing numeric segments indicate an ID-ish parameter
        segs = [s for s in p.path.split("/") if s]
        if segs and segs[-1].isdigit():
            meta["path_params"].add("{id}")

        # Flags for LFI-ish params
        if any(name.lower() in LFIISH_PARAMS for name in params):
            meta["flags"]["lfi_prone"] = True

        # Flags for SQLi-ish params
        if any(name.lower() in SQLIISH_PARAMS for name in params) or "{id}" in meta["path_params"]:
            meta["flags"]["sqli_prone"] = True

        # Also add to seed pages if interesting
        if any(s in key.lower() for s in ["/login", "/register", "/user", "/profile", "/post", "/api", "/search", "/flag", "/terms", "/privacy"]):
            self._enqueue_seed(key)

    # --------------------------
    # Scoring / pattern scanning
    # --------------------------

    def _score_login_page(self, url: str, html: str) -> Tuple[int, List[str], List[str]]:
        score = 0
        hints: List[str] = []
        for pat in LOGIN_URL_PATTERNS:
            if pat.search(url):
                score += 4
                hints.append(f"URL matches {pat.pattern}")

        soup = BeautifulSoup(html, "html.parser")
        if soup.find("input", {"type": "password"}):
            score += 4
            hints.append("Contains password input field")

        text = soup.get_text(separator=" ", strip=True).lower()
        for kw in LOGIN_KEYWORDS:
            if kw in text:
                score += 1
                hints.append(f"Keyword '{kw}' found")

        # DB error strings visible on login pages are high-value for SQLi
        db_errors = []
        for pat in DB_ERROR_PATTERNS:
            m = pat.search(html)
            if m:
                snip = m.group(0)[:120]
                db_errors.append(snip)
                score += 3

        return min(score, 10), hints, db_errors

    def _scan_patterns(self, source_url: str, text: str) -> None:
        for regex, label, severity in self.patterns:
            for m in regex.finditer(text):
                snippet = m.group(0)
                if len(snippet) > 120:
                    snippet = snippet[:120] + "..."
                self.pattern_matches.append(
                    {
                        "source": source_url,
                        "label": label,
                        "severity": severity,
                        "match": snippet,
                    }
                )
