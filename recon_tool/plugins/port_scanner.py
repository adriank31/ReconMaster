"""
port_scanner.py
---------------

This plugin performs multi‑protocol port scanning using the `nmap` Python
bindings.  It detects open TCP and UDP ports and attempts to identify the
services running on those ports.  Results are written to a JSON file
named ``ports.json`` inside the session directory for each host.

Unlike AutoRecon's port scanning subsystem, this implementation is
completely original.  It runs nmap in a background thread so as not to
block the event loop, and exposes only the relevant results via a
simple data structure.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Dict, List, Any

try:
    import nmap  # type: ignore
except ImportError:
    nmap = None  # Will be checked during setup

from recon_tool.core import BasePlugin, ScanContext


class PortScannerPlugin(BasePlugin):
    name = "PortScanner"
    description = "Perform TCP/UDP port scanning and service detection using nmap"
    priority = 10

    def __init__(self, context: ScanContext) -> None:
        super().__init__(context)
        self._scanner: "nmap.PortScanner" | None = None

    async def setup(self) -> None:
        """Initialise the nmap scanner if available.

        If the `python-nmap` binding or the underlying `nmap` binary is not
        available, the plugin will fall back to a basic TCP connect scan.
        """
        if nmap is not None:
            try:
                self._scanner = nmap.PortScanner()
            except Exception:
                # Could not initialise nmap (maybe nmap binary missing)
                self._scanner = None
        else:
            self._scanner = None

    async def scan_target(self, target: str, out_dir: Path) -> None:
        """Scan a single host and write port information to disk."""
        # Use the logging helper for consistent colour and file logging
        self.log(f"Scanning {target} for open ports...", out_dir)
        if self._scanner is not None:
            # Use nmap if available
            try:
                scan_results = await asyncio.to_thread(self._run_scan_nmap, target)
            except Exception as exc:
                # Log failure and fall back
                self.log(f"nmap scan failed: {exc}. Falling back to basic scan.", out_dir, level="WARN")
                scan_results = await self._basic_tcp_scan(target)
        else:
            # Fall back to basic TCP scan
            scan_results = await self._basic_tcp_scan(target)
        # Persist results
        out_file = out_dir / "ports.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(scan_results, f, indent=2)
        self.log(
            f"Completed port scan on {target}: {len(scan_results['ports'])} ports found",
            out_dir,
        )

    def _run_scan_nmap(self, target: str) -> Dict[str, Any]:
        """
        Run a TCP/UDP scan using nmap, taking into account custom port scopes
        defined on the scan context (e.g., --tcp-ports or --udp-ports).  The
        function returns a dictionary with the host and a list of port
        dictionaries.  Service detection (-sV) is always enabled.  If UDP
        scanning is requested and root privileges are available, -sU is used.
        """
        assert self._scanner is not None
        # Determine root privileges (affects scanning technique)
        is_root = os.geteuid() == 0
        args = self._build_nmap_args(is_root)
        # Launch the scan
        self._scanner.scan(target, arguments=args)
        nm = self._scanner
        ports: List[Dict[str, str]] = []
        # Extract results into a simpler structure
        for proto in nm[target].all_protocols():
            for port in nm[target][proto].keys():
                state = nm[target][proto][port].get("state", "unknown")
                service = nm[target][proto][port].get("name", "?")
                product = nm[target][proto][port].get("product", "")
                ports.append(
                    {
                        "protocol": proto,
                        "port": int(port),
                        "state": state,
                        "service": service,
                        "product": product,
                    }
                )
        return {"host": target, "ports": ports}

    def _build_nmap_args(self, is_root: bool) -> str:
        """
        Construct nmap command-line arguments based on the scan context's
        requested TCP/UDP port scopes.  Supports comma-separated lists,
        numeric ranges and presets like 'top100' or 'top1000'.  Returns a
        string of arguments to pass to `nmap.PortScanner.scan`.
        """
        # Base scan flags
        tcp_flag = "-sS" if is_root else "-sT"
        udp_flag = "-sU"
        # Always enable version detection
        svc_flag = "-sV"
        args_parts: List[str] = [tcp_flag, svc_flag]
        # Determine port specifications
        tcp_spec = self.context.tcp_ports
        udp_spec = self.context.udp_ports
        # Helper to parse explicit port list or ranges into nmap syntax
        def parse_port_list(spec: str) -> str:
            tokens = []
            parts = [p.strip() for p in spec.split(",") if p.strip()]
            for part in parts:
                # Accept ranges like 1-1000
                tokens.append(part)
            return ",".join(tokens)
        # If preset specified, convert to top ports
        top_ports_tcp: Optional[int] = None
        top_ports_udp: Optional[int] = None
        explicit_tcp: Optional[str] = None
        explicit_udp: Optional[str] = None
        if tcp_spec:
            low = tcp_spec.lower()
            if low in ("top100", "top1000"):
                top_ports_tcp = int(low[3:])  # extract number from top100 etc.
            else:
                explicit_tcp = parse_port_list(tcp_spec)
        if udp_spec:
            low = udp_spec.lower()
            if low in ("top100", "top1000"):
                top_ports_udp = int(low[3:])
            else:
                explicit_udp = parse_port_list(udp_spec)
        # Build arguments
        # Add UDP scan flag only if UDP ports requested or preset set
        if explicit_udp or top_ports_udp:
            args_parts.append(udp_flag)
        # Build port specification
        if top_ports_tcp or top_ports_udp:
            # Use the maximum of requested top counts because nmap uses a single --top-ports value
            n = 0
            if top_ports_tcp:
                n = max(n, top_ports_tcp)
            if top_ports_udp:
                n = max(n, top_ports_udp)
            if n == 0:
                n = 100
            args_parts.append(f"--top-ports {n}")
        else:
            port_args: List[str] = []
            if explicit_tcp:
                port_args.append(f"T:{explicit_tcp}")
            if explicit_udp:
                port_args.append(f"U:{explicit_udp}")
            if port_args:
                args_parts.append("-p " + ",".join(port_args))
            else:
                # Default: scan all TCP ports
                args_parts.append("-p-")
        # Only return open ports
        args_parts.append("--open")
        return " ".join(args_parts)

    async def _basic_tcp_scan(self, target: str) -> Dict[str, Any]:
        """Fallback port scanner using simple TCP connect attempts.

        Scans the first 1024 TCP ports to identify open services.  This is
        considerably slower and less accurate than nmap but ensures the
        plugin does not fail outright when nmap is unavailable.
        """
        import socket
        ports: List[Dict[str, str]] = []
        # Determine which TCP ports to check based on context
        port_list: List[int] = []
        spec = self.context.tcp_ports
        if spec:
            low = spec.lower()
            if low in ("top100", "top1000"):
                # Basic scanner cannot determine top N ports; approximate by scanning 1-100 or 1-1000
                limit = int(low[3:])
                port_list = list(range(1, limit + 1))
            else:
                # parse comma-separated list and ranges
                for part in spec.split(","):
                    part = part.strip()
                    if not part:
                        continue
                    if "-" in part:
                        try:
                            start, end = part.split("-", 1)
                            start_i = int(start)
                            end_i = int(end)
                            port_list.extend(range(start_i, end_i + 1))
                        except Exception:
                            continue
                    else:
                        try:
                            port_list.append(int(part))
                        except Exception:
                            continue
        if not port_list:
            # Default: scan standard port range 1-1024
            port_list = list(range(1, 1025))
        for port in port_list:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.3)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        ports.append(
                            {
                                "protocol": "tcp",
                                "port": port,
                                "state": "open",
                                "service": "unknown",
                                "product": "",
                            }
                        )
            except Exception:
                continue
        return {"host": target, "ports": ports}