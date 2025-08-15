"""
service_scanner.py
------------------

This plugin performs service‑specific enumeration using nmap scripts based
on the open ports discovered by the port scanner.  It inspects the
``ports.json`` file produced by the port scanner plugin and selectively
runs lightweight nmap NSE scripts against interesting services.  The
outputs are aggregated into a ``services.json`` file.

The scanning strategy here deliberately avoids heavy exploitation.  It
provides a starting point for manual investigation and ensures parity
with typical reconnaissance workflows.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    import nmap  # type: ignore
except ImportError:
    nmap = None

from recon_tool.core import BasePlugin, ScanContext


class ServiceScannerPlugin(BasePlugin):
    name = "ServiceScanner"
    description = "Run service‑specific nmap scripts based on open ports"
    priority = 20

    def __init__(self, context: ScanContext) -> None:
        super().__init__(context)
        self._scanner: "nmap.PortScanner" | None = None

    async def setup(self) -> None:
        """Initialise the nmap scanner or disable service scanning."""
        if nmap is not None:
            try:
                self._scanner = nmap.PortScanner()
            except Exception:
                self._scanner = None
        else:
            self._scanner = None

    async def scan_target(self, target: str, out_dir: Path) -> None:
        # If nmap is unavailable, skip service enumeration
        if self._scanner is None:
            self.log(
                "python-nmap is not installed or nmap binary missing; skipping service enumeration",
                out_dir,
                level="WARN",
            )
            return
        ports_file = out_dir / "ports.json"
        if not ports_file.exists():
            self.log(f"No ports.json found for {target}, skipping service scanning", out_dir, level="WARN")
            return
        with open(ports_file, "r", encoding="utf-8") as f:
            port_data = json.load(f)
        ports: List[Dict[str, Any]] = port_data.get("ports", [])
        service_targets: Dict[str, List[int]] = {}
        # Map services of interest to list of ports
        for entry in ports:
            service = entry.get("service", "").lower()
            port = entry.get("port")
            proto = entry.get("protocol")
            if service in ["http", "https", "http-proxy"]:
                service_targets.setdefault("http", []).append(port)
            elif service.startswith("ssh"):
                service_targets.setdefault("ssh", []).append(port)
            elif service.startswith("smb") or service in ["netbios-ssn", "microsoft-ds"]:
                service_targets.setdefault("smb", []).append(port)
            elif service.startswith("ftp"):
                service_targets.setdefault("ftp", []).append(port)
            # Extend with more service categories as needed

        # Perform scans per service category
        results: Dict[str, Any] = {}
        for svc, svc_ports in service_targets.items():
            script_args, description = self._nmap_command_for_service(svc)
            for port in svc_ports:
                scan_res = await asyncio.to_thread(self._run_nmap_script, target, port, script_args)
                results[f"{svc}:{port}"] = {
                    "description": description,
                    "output": scan_res,
                }
        # Write results to file
        out_file = out_dir / "services.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
            self.log("Completed service enumeration on {}".format(target), out_dir)

    def _nmap_command_for_service(self, service: str) -> Tuple[str, str]:
        """Return NSE script arguments and a description for the given service."""
        if service == "http":
            # Use simple HTTP scripts
            return "--script=http-title,http-headers,http-methods", "HTTP enumeration"
        if service == "ssh":
            return "--script=ssh-hostkey", "SSH host key fingerprint"
        if service == "smb":
            return "--script=smb-os-discovery,smb-enum-users", "SMB OS and user enumeration"
        if service == "ftp":
            return "--script=ftp-anon,ftp-syst", "FTP anonymous and system information"
        # Default: no scripts
        return "", "No specific enumeration"

    def _run_nmap_script(self, target: str, port: int, script_args: str) -> str:
        assert self._scanner is not None
        args = f"-p {port} {script_args}"
        try:
            self._scanner.scan(target, arguments=args)
            host_result = self._scanner[target]
            return host_result.__str__()
        except Exception as exc:
            return f"Error running nmap script on port {port}: {exc}"