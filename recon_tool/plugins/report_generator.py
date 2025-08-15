"""
Report Generator (enhanced: SQLi + LFI + Web intel)
---------------------------------------------------

Builds a consolidated Markdown and HTML report from artifacts written by other
plugins. Robust to missing files and differing JSON shapes.

Inputs (all optional except 'ports/services' if present):
- ports.json                      -> open port list (supports dict or list shapes)
- services.json                   -> keyed map of service -> {description, output}
- web/paths.json                  -> discovered pages/paths
- web/login_candidates.json       -> login page candidates (if produced)
- web/forms.json                  -> discovered forms (if produced)
- web/param_seeds.json            -> seeded query parameter names per URL (if produced)
- patterns.json                   -> pattern matches recorded by dir brute (if produced)
- sqli_attempts.json              -> per-attempt log from SQLiAnalyzer
- sqli_findings.json              -> confirmed SQLi results
- lfi_attempts.json               -> per-attempt log from LFIScanner
- lfi_findings.json               -> confirmed LFI results

Outputs:
- report.json     -> machine-readable summary
- report.md       -> human-readable markdown
- report.html     -> simple HTML wrapper for the markdown content
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from recon_tool.core import BasePlugin, ScanContext


class ReportGeneratorPlugin(BasePlugin):
    name = "ReportGenerator"
    description = "Collate results and generate Markdown/HTML reports"
    priority = 90

    # caps to keep the report readable
    MAX_WEB_ROWS = 500
    MAX_ATTEMPT_ROWS = 300
    MAX_PATTERN_ROWS = 200
    MAX_FORMS_ROWS = 120
    MAX_PARAM_SEEDS = 200

    async def scan_target(self, target: str, out_dir: Path) -> None:
        summary: Dict[str, Any] = {}

        # ---- Core host/service info
        ports_file = out_dir / "ports.json"
        services_file = out_dir / "services.json"
        summary["ports"] = self._load_json(ports_file, {})
        summary["services"] = self._load_json(services_file, {})

        # ---- Web intel
        web_dir = out_dir / "web"
        paths_file = web_dir / "paths.json"
        login_file = web_dir / "login_candidates.json"
        forms_file = web_dir / "forms.json"
        seeds_file = web_dir / "param_seeds.json"
        patterns_file = out_dir / "patterns.json"  # written by dir brute when patterns are enabled

        summary["web_paths"] = self._load_json(paths_file, [])
        summary["web_login_candidates"] = self._load_json(login_file, [])
        summary["web_forms"] = self._load_json(forms_file, [])
        summary["web_param_seeds"] = self._load_json(seeds_file, {})
        summary["pattern_matches"] = self._load_json(patterns_file, [])

        # ---- SQLi artifacts
        sqli_findings_file = out_dir / "sqli_findings.json"
        sqli_attempts_file = out_dir / "sqli_attempts.json"
        summary["sqli_findings"] = self._load_json(sqli_findings_file, [])
        summary["sqli_attempts"] = self._load_json(sqli_attempts_file, [])

        # ---- LFI artifacts
        lfi_findings_file = out_dir / "lfi_findings.json"
        lfi_attempts_file = out_dir / "lfi_attempts.json"
        summary["lfi_findings"] = self._load_json(lfi_findings_file, [])
        summary["lfi_attempts"] = self._load_json(lfi_attempts_file, [])

        # ---- Derived overview numbers
        summary["overview"] = self._build_overview(summary)

        # ---- Write JSON summary for other consumers
        with open(out_dir / "report.json", "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        # ---- Markdown & HTML
        md = self._generate_markdown_report(summary, target)
        with open(out_dir / "report.md", "w", encoding="utf-8") as f:
            f.write(md)
        html = self._wrap_html(md)
        with open(out_dir / "report.html", "w", encoding="utf-8") as f:
            f.write(html)

        self.log("Report generated", out_dir, level="INFO")

    # ------------------------------------------------------------------
    # Loading helpers
    # ------------------------------------------------------------------

    def _load_json(self, path: Path, default: Any) -> Any:
        try:
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return default

    # ------------------------------------------------------------------
    # Overview
    # ------------------------------------------------------------------

    def _build_overview(self, s: Dict[str, Any]) -> Dict[str, Any]:
        # open ports: support both dict {"host":..., "ports":[...]} and list
        open_ports = []
        ports_obj = s.get("ports")
        if isinstance(ports_obj, dict) and "ports" in ports_obj:
            open_ports = ports_obj.get("ports", [])
        elif isinstance(ports_obj, list):
            open_ports = ports_obj
        # Count by service
        services_counter = Counter([p.get("service", "") for p in open_ports if isinstance(p, dict)])

        overview = {
            "open_ports_count": len(open_ports),
            "services_top": services_counter.most_common(10),
            "web_paths_count": len(s.get("web_paths", [])),
            "web_login_candidates_count": len(s.get("web_login_candidates", [])),
            "forms_count": len(s.get("web_forms", [])),
            "sqli_findings_count": len(s.get("sqli_findings", [])),
            "sqli_attempts_count": len(s.get("sqli_attempts", [])),
            "lfi_findings_count": len(s.get("lfi_findings", [])),
            "lfi_attempts_count": len(s.get("lfi_attempts", [])),
            "pattern_matches_count": len(s.get("pattern_matches", [])),
        }
        return overview

    # ------------------------------------------------------------------
    # Markdown report
    # ------------------------------------------------------------------

    def _generate_markdown_report(self, summary: Dict[str, Any], target: str) -> str:
        safe = self._safe  # local alias for escaping in tables

        md: List[str] = []
        md.append(f"# Reconnaissance Report for {safe(target)}\n")

        # Overview numbers
        ov = summary.get("overview", {})
        md.append("## Overview")
        md.append("")
        md.append("| Metric | Count |")
        md.append("|---|---:|")
        for k, label in [
            ("open_ports_count", "Open Ports"),
            ("web_paths_count", "Web Paths Discovered"),
            ("web_login_candidates_count", "Login Page Candidates"),
            ("forms_count", "Forms Detected"),
            ("sqli_findings_count", "SQLi Findings"),
            ("sqli_attempts_count", "SQLi Attempts"),
            ("lfi_findings_count", "LFI Findings"),
            ("lfi_attempts_count", "LFI Attempts"),
            ("pattern_matches_count", "Pattern Matches"),
        ]:
            md.append(f"| {label} | {ov.get(k, 0)} |")

        # -------------------- Open ports --------------------
        ports_obj = summary.get("ports", {})
        ports_list: List[Dict[str, Any]] = []
        if isinstance(ports_obj, dict) and "ports" in ports_obj:
            ports_list = ports_obj.get("ports", [])
        elif isinstance(ports_obj, list):
            ports_list = ports_obj
        if ports_list:
            md.append("\n## Open Ports")
            md.append("| Port | Protocol | Service | Product |")
            md.append("|---:|:---:|---|---|")
            for p in ports_list:
                if not isinstance(p, dict):
                    continue
                md.append(
                    f"| {safe(p.get('port',''))} | {safe(p.get('protocol') or p.get('proto',''))} | "
                    f"{safe(p.get('service',''))} | {safe(p.get('product',''))} |"
                )

        # -------------------- Services --------------------
        services = summary.get("services", {})
        if isinstance(services, dict) and services:
            md.append("\n## Service Enumeration")
            for k, v in services.items():
                try:
                    desc = v.get("description", "")
                    out = v.get("output", "")
                except Exception:
                    # if shape is unexpected, just print string
                    desc, out = "", str(v)
                md.append(f"\n**{safe(k)}** — {safe(desc)}\n")
                md.append("```")
                md.append(str(out))
                md.append("```")

        # -------------------- Web paths --------------------
        web_paths = summary.get("web_paths", []) or []
        if web_paths:
            md.append("\n## Web Paths Discovered")
            md.append("| URL | Status | Length | Content-Type | Title |")
            md.append("|---|---:|---:|---|---|")
            for w in web_paths[: self.MAX_WEB_ROWS]:
                if not isinstance(w, dict):
                    continue
                md.append(
                    f"| {safe(w.get('url',''))} | {safe(w.get('status',''))} | {safe(w.get('length',''))} | "
                    f"{safe(w.get('content_type',''))} | {safe(w.get('title',''))} |"
                )
            if len(web_paths) > self.MAX_WEB_ROWS:
                md.append(f"\n_Only showing first {self.MAX_WEB_ROWS} of {len(web_paths)} rows._")

        # Login candidates (legacy or computed)
        login_candidates = summary.get("web_login_candidates", []) or []
        if login_candidates:
            md.append("\n## Login Page Candidates")
            md.append("| URL | Score | Hints | DB Errors |")
            md.append("|---|---:|---|---|")
            for l in login_candidates:
                if not isinstance(l, dict):
                    continue
                hints = l.get("hints") or l.get("login_hints") or []
                if isinstance(hints, list):
                    hints = ", ".join(map(self._safe, map(str, hints)))
                db_errs = l.get("db_errors") or []
                if isinstance(db_errs, list):
                    db_errs = ", ".join(map(self._safe, map(str, db_errs)))
                md.append(
                    f"| {safe(l.get('url',''))} | {safe(l.get('score',''))} | {hints} | {db_errs} |"
                )

        # Forms
        forms = summary.get("web_forms", []) or []
        if forms:
            md.append("\n## Forms Detected")
            md.append("| Action | Method | Suspicious Inputs | All Inputs |")
            md.append("|---|:---:|---|---|")
            for f in forms[: self.MAX_FORMS_ROWS]:
                if not isinstance(f, dict):
                    continue
                action = f.get("action") or f.get("url") or ""
                method = (f.get("method") or "").upper()
                inputs = f.get("inputs") or {}
                suspects = [k for k in inputs.keys() if self._is_suspect_param(k)]
                md.append(
                    f"| {safe(action)} | {safe(method)} | {safe(', '.join(suspects))} | {safe(', '.join(inputs.keys()))} |"
                )
            if len(forms) > self.MAX_FORMS_ROWS:
                md.append(f"\n_Only showing first {self.MAX_FORMS_ROWS} of {len(forms)} forms._")

        # Param seeds
        param_seeds = summary.get("web_param_seeds", {}) or {}
        if isinstance(param_seeds, dict) and param_seeds:
            md.append("\n## Seeded Query Parameters")
            md.append("| URL | Param Candidates |")
            md.append("|---|---|")
            shown = 0
            for url, names in param_seeds.items():
                if shown >= self.MAX_PARAM_SEEDS:
                    break
                names_str = ", ".join([self._safe(str(n)) for n in (names or [])])
                md.append(f"| {safe(url)} | {names_str} |")
                shown += 1
            if len(param_seeds) > self.MAX_PARAM_SEEDS:
                md.append(f"\n_Only showing first {self.MAX_PARAM_SEEDS} URLs with seeds._")

        # Pattern matches
        patterns = summary.get("pattern_matches", []) or []
        if patterns:
            md.append("\n## Pattern Matches")
            md.append("| Source | Label | Severity | Snippet |")
            md.append("|---|---|:---:|---|")
            for pm in patterns[: self.MAX_PATTERN_ROWS]:
                if not isinstance(pm, dict):
                    continue
                md.append(
                    f"| {safe(pm.get('source',''))} | {safe(pm.get('label',''))} | "
                    f"{safe(pm.get('severity',''))} | {safe(pm.get('match',''))} |"
                )
            if len(patterns) > self.MAX_PATTERN_ROWS:
                md.append(f"\n_Only showing first {self.MAX_PATTERN_ROWS} of {len(patterns)} matches._")

        # -------------------- SQLi --------------------
        sqli_attempts = summary.get("sqli_attempts", []) or []
        sqli_findings = summary.get("sqli_findings", []) or []

        if sqli_attempts:
            md.append("\n## SQLi Attempts Summary")
            agg = self._group_attempts(sqli_attempts, keys=("technique",))
            md.append("| Technique | Attempts | Successes | Success Rate |")
            md.append("|---|---:|---:|---:|")
            for row in agg:
                rate = f"{(100.0 * row['successes'] / max(1, row['attempts'])):.1f}%"
                md.append(f"| {safe(row['technique'])} | {row['attempts']} | {row['successes']} | {rate} |")

            # Sample detailed attempts
            md.append("\n### Sample SQLi Attempts")
            md.append("| URL | Parameter | Technique | Payload | Success | Notes |")
            md.append("|---|---|---|---|:---:|---|")
            for a in sqli_attempts[: self.MAX_ATTEMPT_ROWS]:
                if not isinstance(a, dict):
                    continue
                md.append(
                    f"| {safe(a.get('url',''))} | {safe(a.get('parameter',''))} | {safe(a.get('technique',''))} "
                    f"| {safe(a.get('payload',''))} | {'✅' if a.get('success') else '❌'} | {safe(a.get('notes',''))} |"
                )
            if len(sqli_attempts) > self.MAX_ATTEMPT_ROWS:
                md.append(f"\n_Only showing first {self.MAX_ATTEMPT_ROWS} of {len(sqli_attempts)} attempts._")

        if sqli_findings:
            md.append("\n## SQL Injection Findings")
            md.append("| URL | Location | Technique | Payload | DBMS | Evidence |")
            md.append("|---|---|---|---|---|---|")
            for f in sqli_findings:
                if not isinstance(f, dict):
                    continue
                md.append(
                    f"| {safe(f.get('url',''))} | {safe(f.get('parameter',''))} | {safe(f.get('injection_type',''))} "
                    f"| {safe(f.get('vector') or f.get('payload',''))} | {safe(f.get('dbms',''))} | {safe(f.get('evidence',''))} |"
                )

        # -------------------- LFI --------------------
        lfi_attempts = summary.get("lfi_attempts", []) or []
        lfi_findings = summary.get("lfi_findings", []) or []

        if lfi_attempts:
            md.append("\n## LFI Attempts Summary")
            agg = self._group_attempts(lfi_attempts, keys=("method", "parameter"))
            md.append("| Method | Parameter | Attempts | Successes | Success Rate |")
            md.append("|---|---|---:|---:|---:|")
            for row in agg:
                rate = f"{(100.0 * row['successes'] / max(1, row['attempts'])):.1f}%"
                md.append(f"| {safe(row['method'])} | {safe(row['parameter'])} | {row['attempts']} | {row['successes']} | {rate} |")

            # Sample detailed attempts
            md.append("\n### Sample LFI Attempts")
            md.append("| URL | Method | Parameter | Payload | Success | Notes |")
            md.append("|---|:---:|---|---|:---:|---|")
            for a in lfi_attempts[: self.MAX_ATTEMPT_ROWS]:
                if not isinstance(a, dict):
                    continue
                md.append(
                    f"| {safe(a.get('url',''))} | {safe(a.get('method',''))} | {safe(a.get('parameter',''))} "
                    f"| {safe(a.get('payload',''))} | {'✅' if a.get('success') else '❌'} | {safe(a.get('notes',''))} |"
                )
            if len(lfi_attempts) > self.MAX_ATTEMPT_ROWS:
                md.append(f"\n_Only showing first {self.MAX_ATTEMPT_ROWS} of {len(lfi_attempts)} attempts._")

        if lfi_findings:
            md.append("\n## LFI Findings")
            md.append("| URL | Method | Parameter | Payload | Evidence |")
            md.append("|---|:---:|---|---|---|")
            for f in lfi_findings:
                if not isinstance(f, dict):
                    continue
                md.append(
                    f"| {safe(f.get('url',''))} | {safe(f.get('method',''))} | {safe(f.get('parameter',''))} "
                    f"| {safe(f.get('payload',''))} | {safe(f.get('evidence',''))} |"
                )

        md.append("")  # newline at EOF
        return "\n".join(md)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _safe(self, v: Any) -> str:
        """Escape table-breaking characters while keeping it readable."""
        s = str(v)
        s = s.replace("\n", " ").replace("\r", " ")
        s = s.replace("|", r"\|")
        return s.strip()

    def _is_suspect_param(self, name: str) -> bool:
        n = name.lower()
        return bool(re.search(r"(file|path|dir|include|inc|tpl|template|page|view|module|theme|layout|filename)", n))

    def _group_attempts(self, rows: List[Dict[str, Any]], keys: Tuple[str, ...]) -> List[Dict[str, Any]]:
        bucket: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        for r in rows:
            k = tuple(r.get(key, "") for key in keys)
            if k not in bucket:
                entry = {key: r.get(key, "") for key in keys}
                entry["attempts"] = 0
                entry["successes"] = 0
                bucket[k] = entry
            bucket[k]["attempts"] += 1
            if r.get("success"):
                bucket[k]["successes"] += 1
        # Stable order: most attempts first
        ordered = sorted(bucket.values(), key=lambda x: (-x["attempts"], -x["successes"]))
        # Expand single-key buckets with a consistent field name
        if keys == ("technique",) and not any("technique" not in b for b in ordered):
            return ordered
        return ordered

    def _wrap_html(self, md: str) -> str:
        # minimal Markdown -> HTML: only headers + code blocks styled; keep tables as-is
        css = """
        <style>
        body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; table-layout: fixed; }
        th, td { border: 1px solid #ddd; padding: 6px 8px; vertical-align: top; word-wrap: break-word; }
        th { background: #f5f5f5; }
        code, pre { white-space: pre-wrap; word-wrap: break-word; }
        h1, h2, h3 { margin-top: 1.2em; }
        </style>
        """
        html = md
        html = html.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        # preserve code fences
        html = html.replace("```", "\n</pre>\n").replace("\n</pre>\n", "<pre>")
        # blank lines -> <br><br> (light)
        html = html.replace("\n\n", "<br><br>")
        # headers
        html = re.sub(r"^# (.+)$", r"<h1>\1</h1>", html, flags=re.MULTILINE)
        html = re.sub(r"^## (.+)$", r"<h2>\1</h2>", html, flags=re.MULTILINE)
        html = re.sub(r"^### (.+)$", r"<h3>\1</h3>", html, flags=re.MULTILINE)
        # keep markdown tables as-is (rendered by CSS)
        return f"<!doctype html><meta charset='utf-8'>{css}<div>{html}</div>"
