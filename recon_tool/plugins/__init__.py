"""
Plugins package
===============

All scanner plugins live in this package.  To add a new plugin, create a
module in this directory that defines a subclass of
``recon_tool.core.BasePlugin``.  The plugin manager will automatically
discover and register it.  Do not import anything at module import time
that could slow down the startup of the tool; heavy imports should be
performed lazily in the plugin's ``setup`` method.

Plugins provided out of the box include:

* ``port_scanner`` – performs TCP/UDP port scanning and service detection.
* ``service_scanner`` – runs service‑specific enumeration based on open ports.
* ``dir_brute_forcer`` – discovers files and directories on web servers and
  identifies login forms.
* ``sqli_analyzer`` – analyses discovered endpoints for SQL injection
  vulnerabilities using simple payloads and optionally the sqlmap API.
* ``report_generator`` – collates results from other plugins into JSON and
  Markdown reports.
"""

__all__ = [
    "port_scanner",
    "service_scanner",
    "dir_brute_forcer",
    "sqli_analyzer",
    "report_generator",
]