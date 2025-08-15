# Recon Tool — Web Recon + SQLi/LFI Orchestrator

A fast, modular reconnaissance framework for CTFs and lab environments that chains together:

* TCP port + service enumeration
* Web content discovery (dir brute) with login detection and pattern scanning
* **Run-all SQLi analyzer** (GET/POST parameters, headers, cookies, JSON, basic UNION checks, login bypass)
* **LFI / path traversal scanner** (GET + POST params, php\://filter decoding, optional log poisoning)
* Unified reporting (Markdown + HTML) with full attempt logs

⚠️ **For authorized testing only.** You are responsible for ensuring you have written permission to scan a target.

---

## Why this project?

Most single-purpose scanners either stop at discovery or bail after the first finding. In CTFs and labs, you usually want **breadth first** (find *all* low-hanging routes) and **no short-circuiting** (collect every SQLi/LFI that fires). This tool:

* Automates the “boring but essential” recon chain end-to-end
* Seeds SQLi/LFI tests from real pages found by the dir brute (including login forms)
* Tries multiple injection surfaces (query params, POST bodies, headers, cookies) without giving up after the first success
* Produces a structured report + raw attempt logs so you can reproduce or pivot

Methodology aligns with OWASP testing guidance for SQL Injection and File Inclusion / Path Traversal.

---

## What it does (capabilities)

* **Port & Service scan**
  Uses Nmap to detect services and grab common HTTP script output (e.g., titles/methods). You’ll see this reflected in `services.json` (e.g., `http-title`, `http-methods`). The behavior corresponds to Nmap’s `http-title`/HTTP NSE ecosystem. 

* **Directory brute (DirBruteForcer)**
  Async enumeration with your chosen wordlist. It:

  * Writes `web/paths.json` with URL, status, and length
  * Scores **login candidates** by URL patterns, password fields, and keywords
  * Scans for DB error signatures (quick SQLi hints)
  * (Optional) loads `patterns.toml` to highlight arbitrary regex matches
  * Seeds later scanners with parameter names, forms, and “well-known” endpoints

  Wordlists: the project plays nicely with **SecLists** (e.g., `Discovery/Web-Content/common.txt`, `raft-small-directories.txt`). 

* **SQLi Analyzer (run-all-and-aggregate)**
  Against discovered endpoints, it tries:

  * Login bypass payloads (boolean) on login forms
  * Error-based/boolean/time-based SQLi on GET params
  * Header injection sinks (e.g., `X-Forwarded-For`, `User-Agent`)
  * Cookie injection sinks (e.g., TrackingId-style)
  * JSON body injections where appropriate
  * Basic UNION scaffolding with `ORDER BY` and marker rotation
    All attempts are logged to `sqli_attempts.json`. All positives go to `sqli_findings.json`.

* **LFI / Path Traversal Scanner**
  Tests suspect GET and POST parameters (`file`, `path`, `page`, `view`, `template`, etc.) with:

  * Raw, URL-encoded, double-encoded, dot-flooded traversal chains
  * Windows and Linux target files (`/etc/passwd`, `/etc/hosts`, `win.ini`, `/proc/*`)
  * `php://filter` base64 source disclosure (auto-detects and decodes)
  * Optional **log poisoning** when `--lfi-aggressive` is set
    Results in `lfi_attempts.json` and `lfi_findings.json`.

  These techniques follow OWASP’s testing guidance for File Inclusion / Path Traversal.

* **Reporting**
  `report.md` and `report.html` consolidate open ports, services, web paths, SQLi attempts/findings, and more.

---

## Project layout (outputs)

For each run and target:

```
results/<TARGET>/session_<timestamp>/
├─ ports.json
├─ services.json
├─ scanner.log
├─ report.json
├─ report.md
├─ report.html
├─ sqli_attempts.json
├─ sqli_findings.json
├─ lfi_attempts.json
├─ lfi_findings.json
└─ web/
   ├─ paths.json
   ├─ login_candidates.json
   ├─ forms.json             (if collected by dir brute)
   └─ param_seeds.json       (if collected by dir brute)
```

---

## Installation

### Requirements

* Python 3.10+
* Nmap (for port/service enumeration)
* Wordlists (we recommend **SecLists**)

### Setup (virtualenv)

```bash
# 1) Create and activate a virtual environment
python3 -m venv ~/reconenv
source ~/reconenv/bin/activate

# 2) Install dependencies
pip install --upgrade pip
pip install -r recon_tool/requirements.txt
```

### Running with sudo (preserve env)

If you want to keep the virtualenv interpreter while using elevated privileges (e.g., raw socket scans):

```bash
sudo -E /home/$USER/reconenv/bin/python -m recon_tool.main <TARGET> [flags...]
```

---

## Quick start

**Basic scan (auto-confirm invasive checks):**

```bash
sudo -E /home/$USER/reconenv/bin/python -m recon_tool.main 10.10.10.10 \
  --auto-confirm
```

**Web-focused run using a small wordlist + balanced SQLi:**

```bash
sudo -E /home/$USER/reconenv/bin/python -m recon_tool.main 10.10.10.10 \
  --wordlist /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt \
  --tcp-ports top100 --auto-confirm --rate 6 --sqli-mode balanced
```

**Multiple targets from file:**

```bash
sudo -E /home/$USER/reconenv/bin/python -m recon_tool.main \
  --targets-file targets.txt --auto-confirm
```

---

## Command-line reference

All flags below map directly to `main.py`.

### Targets

* `targets` (positional): One or more hosts or CIDRs (space-separated).
* `--targets-file <path>`: File with one target per line.

### Port scope

* `--tcp-ports <preset|list>`: `top100`, `top1000`, `web-only`, `all`, or comma list (e.g., `80,443,22`).
* `--udp-ports <preset|list>`: `top100`, `top1000`, or comma list.

### Web enumeration

* `--wordlist <path>`: Wordlist for directory brute (e.g., SecLists `common.txt` or `raft-small-directories.txt`).
### Behavior / UX

* `--auto-confirm`: Skip prompts for invasive checks (SQLi/LFI).
* `--rate <int>`: Target request rate (req/sec) for HTTP modules (pacing).
* `--no-color`: Disable colored console output.

### Patterns / hints (optional)

* `--patterns <patterns.toml>`: Regex labels and severities to auto-highlight in responses.
* `--hints <hints.yaml>`: Service-specific manual follow-ups (displayed in report if supported).

### LFI / Traversal

* `--lfi-aggressive`: Enable log poisoning attempts and additional log includes.

### SQLi engine (run-all & aggregate)

* `--sqli-run-all`: Run every technique and collect all findings (default: on).
* `--sqli-mode {fast|balanced|deep}`: Intensity dial; controls payload counts/timeouts internally.
* `--sqli-max-per-endpoint <int>`: Cap payloads per technique per endpoint (default: 12).
* `--sqli-timeout <seconds>`: Per-request HTTP timeout for SQLi checks (default: 10).
* `--sqli-confirmations <int>`: Confirmations for time-based hits (e.g., require 2/3; default: 2).
* `--sqli-oob-domain <domain>`: (Advanced/opt-in) Collaborator domain for OOB tests.

---

## Tuning & performance tips

* **Start with smaller wordlists** for discovery to keep runs short (e.g., SecLists `raft-small-directories.txt` or `common.txt`). You can expand later if needed.
* **Use `--sqli-mode fast`** and lower `--sqli-max-per-endpoint` if you just want quick coverage.
* **Increase `--rate` cautiously**. Going too high risks timeouts or WAF throttling.
* **Scope ports** with `--tcp-ports web-only` when you only care about the web stack.
* **Disable aggressive LFI** (`--lfi-aggressive` off) if you’re short on time; poisoning adds extra passes.
* **Use `--targets-file`** to batch work but keep each target’s session isolated.

---

## How it works (high-level pipeline)

1. **Port scan** → writes `ports.json` (open TCP/UDP per scope)
2. **Service enumeration** → writes `services.json` (e.g., HTTP titles/methods) — leverages Nmap HTTP NSE behavior.
3. **Dir brute** → writes `web/paths.json` + `web/login_candidates.json` and optional `web/forms.json`, `web/param_seeds.json`
4. **SQLi analyzer** (run-all) → writes `sqli_attempts.json` and `sqli_findings.json`

   * Techniques: login bypass, error/boolean/time-based params, headers, cookies, JSON, basic UNION, placeholder second-order hooks.
   * Fingerprints DB errors and notes timing-based evidence.
   * Inspired by OWASP SQL Injection testing guidance.
5. **LFI scanner** → writes `lfi_attempts.json` and `lfi_findings.json`

   * Traversal chains, php\://filter base64 decoding, optional log poisoning
   * Grounded in OWASP testing guidance for LFI/Path Traversal.
6. **Report generator** → writes `report.md` and `report.html`

---

## Examples

**Balanced recon with small raft list, tuned rate:**

```bash
sudo -E /home/$USER/reconenv/bin/python -m recon_tool.main 10.10.10.10 \
  --wordlist /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt \
  --tcp-ports top100 --auto-confirm --rate 6 --sqli-run-all --sqli-mode balanced
```

**Quick pass (fast SQLi, smaller payload caps):**

```bash
sudo -E /home/$USER/reconenv/bin/python -m recon_tool.main 10.10.10.10 \
  --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt \
  --tcp-ports web-only --auto-confirm --rate 8 \
  --sqli-mode fast --sqli-max-per-endpoint 6
```

**Deep dive (be patient):**

```bash
sudo -E /home/$USER/reconenv/bin/python -m recon_tool.main 10.10.10.10 \
  --wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  --tcp-ports top1000 --auto-confirm --rate 4 \
  --sqli-mode deep --sqli-max-per-endpoint 20 --sqli-confirmations 3 \
  --lfi-aggressive
```

---

## Troubleshooting

* **It’s slow / takes too long**
  Use smaller wordlists, `--sqli-mode fast`, lower `--sqli-max-per-endpoint`, and avoid `--lfi-aggressive` unless needed.

* **No web folder appears**
  Dir brute only runs if an HTTP(S) service is found (e.g., 80/443 or similar). Check `ports.json`.

* **Report shows little output**
  Confirm that `web/paths.json` exists and contains URLs; SQLi/LFI depend on it for seeding.

* **WAF blocks**
  The tool will throttle a bit when it infers blocking patterns, but you may need to reduce `--rate` or limit scope.

---

## Ethical use

Only scan systems you own or have **explicit written permission** to test. Review local laws and your engagement’s rules of engagement before you run any automated testing.

---

## Credits, wordlists & references

* **OWASP Web Security Testing Guide** — SQL Injection, LFI/Path Traversal methodology.
* **SecLists** — community wordlists (`common.txt`, RAFT lists, etc.).
* **Nmap** — HTTP NSE scripts such as `http-title` used during enumeration.

---

## Roadmap ideas

* Smarter deduping of SQLi vector families by response clustering
* Optional integration with sqlmap API for verification
* Auto-crawl to enrich parameter discovery
* Templated exploit PoCs (when safe/legal) for confirmed findings

---

### License

Choose and add a license file that matches how you want others to use this tool (e.g., MIT, Apache-2.0, GPL-3.0).

---

**Happy hacking (ethically)!**
