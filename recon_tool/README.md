# Custom Reconnaissance Tool

This package provides an original reconnaissance framework for network
enumeration and vulnerability discovery. It should work on Linux systems (including Kali) with Python 3.8+
installed.

## Features

- **Modular architecture.**  Scans are implemented as plugins which can be
  enabled/disabled or extended without modifying the core of the tool.
- **Concurrent port scanning.**  Uses the `nmap` Python bindings to perform
  multi‑threaded TCP/UDP scans and service detection.
- **Directory and file discovery.**  Performs asynchronous HTTP requests to
  discover potentially interesting paths, optionally using user‑supplied
  wordlists.  Results are analysed in real time to identify login pages and
  other high‑value targets.
- **Intelligent SQL injection automation.**  When login pages or query
  parameters are detected, a scoring algorithm determines whether SQL
  injection should be attempted.  High‑confidence targets are passed to
  either a custom payload engine or, if available, the `sqlmap` API for
  automated exploitation.
- **Service‑specific scans.**  Additional plugins can be added for SMB,
  HTTP, SSH, etc.  Out of the box the service scanner plugin runs a handful
  of common `nmap` scripts against discovered ports.
- **Structured results.**  Intermediate data is written to JSON files for
  programmatic consumption, while final reports are generated in
  Markdown/HTML with a visual hierarchy to aid human analysts.

## Usage

The entry point for the tool is `python3 -m recon_tool.main`.  By default it
accepts one or more targets in the form of IP addresses, CIDR ranges or
domain names.  Use `--help` to see all available options.

```
python3 -m recon_tool.main 192.168.56.101 10.10.10.0/24 example.com \
  --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
```

The first run will create a `results` directory in the current working
directory.  Each target receives its own subdirectory containing JSON
artifacts, logs and reports.  Existing results are not overwritten; a
timestamped session directory is created for each scan.

## Dependencies

This project requires the following Python packages:

- `aiohttp` for asynchronous HTTP requests.
- `beautifulsoup4` for HTML parsing.
- `nmap` (the `python-nmap` wrapper) for port scanning and service
  detection.
- `sqlmap-api` or `sqlmapapi` if you wish to leverage the sqlmap API.
- `markdown` for converting Markdown reports to HTML (optional).

Use the provided `requirements.txt` to install dependencies:

```
python3 -m pip install -r requirements.txt
```

## Warning

Automated vulnerability scanning, particularly SQL injection, carries risk.
Always ensure you have proper authorisation before running this tool against
any network or website.  The author of this framework assumes no
responsibility for misuse.

## License

Distributed under the MIT license.  See the `LICENSE` file for details.
