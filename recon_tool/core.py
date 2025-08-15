"""
core.py
-------

This module defines the core abstractions used throughout the reconnaissance
framework.  The classes here are deliberately simple and self‑contained to
facilitate testing and extension.  They provide the minimum scaffolding
necessary to manage targets, plugin execution and result aggregation.

The design differs significantly from AutoRecon's internal classes.  It
introduces a ``Target`` object for each host or network, a ``ScanContext`` to
carry configuration and accumulate findings, and a basic plugin manager for
loading and running scan modules.  Plugins are executed asynchronously
wherever possible to maximise throughput.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import ipaddress
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Iterable, List, Optional, Type


@dataclass
class Target:
    """Represents a single scan target.

    A target can be an IPv4/IPv6 address, a CIDR range or a hostname.  The
    ``raw`` attribute stores the original string provided by the user.  The
    ``hosts`` property expands CIDR ranges into individual addresses on
    demand; for single IPs and hostnames it simply yields the raw value.
    """

    raw: str

    @property
    def hosts(self) -> Iterable[str]:
        try:
            network = ipaddress.ip_network(self.raw, strict=False)
            # Return each host address in the network (skipping network/broadcast)
            for addr in network.hosts():
                yield str(addr)
        except ValueError:
            # Not a CIDR; just return the raw string
            yield self.raw


@dataclass
class ScanContext:
    """Holds configuration and intermediate results for a scan session."""

    wordlist: Optional[str] = None
    rate_limit: float = 5.0  # requests per second for SQLi payloads
    sqlmap_api_url: Optional[str] = None
    results_dir: Path = field(default_factory=lambda: Path(os.getcwd()) / "results")
    plugins: List[str] = field(default_factory=list)
    additional_options: Dict[str, Any] = field(default_factory=dict)

    # Additional configuration options
    # Path to TOML file defining regex patterns for automatic extraction
    patterns_file: Optional[str] = None
    # Path to YAML file defining suggested manual commands per service
    hints_file: Optional[str] = None
    # Custom port scopes (comma separated ranges or presets)
    tcp_ports: Optional[str] = None
    udp_ports: Optional[str] = None
    # Disable colour output to console if set
    no_color: bool = False
    # Path to CVE database (YAML) for vulnerability hints
    cve_file: Optional[str] = None

    def __post_init__(self) -> None:
        # Ensure the results directory exists
        self.results_dir.mkdir(parents=True, exist_ok=True)


class BasePlugin:
    """Abstract base class for all scanner plugins.

    Each plugin is responsible for a discrete piece of functionality, such as
    port scanning or directory brute forcing.  The framework will call
    ``setup`` once at startup, ``scan_target`` for each target, and
    ``teardown`` at the end.  Plugins may override any of these methods.
    """

    name: str = "BasePlugin"
    description: str = ""
    priority: int = 50  # plugins run in ascending order of priority

    def __init__(self, context: ScanContext) -> None:
        self.context = context

    # ------------------------------------------------------------------
    # Logging helper
    # Plugins should call this instead of using print() directly.  It will
    # honour the global colour setting and append messages to the
    # scanner.log file in the target's output directory.  Colour codes
    # follow ANSI escape sequences.  If no colour is requested, plain
    # messages are printed.  The message will be prefixed with the
    # plugin's name for clarity.
    def log(self, message: str, out_dir: Path, level: str = "INFO") -> None:
        """Log a message to both the console and a log file.

        :param message: The message to log.
        :param out_dir: The directory corresponding to the current target
                        session where ``scanner.log`` will be written.
        :param level: The severity level (e.g. INFO, WARN, ERROR) used
                       only for colouring the console output.
        """
        # Determine colour codes based on level
        if not self.context.no_color:
            colour_map = {
                "INFO": "\033[94m",  # blue
                "WARN": "\033[93m",  # yellow
                "ERROR": "\033[91m",  # red
                "DEBUG": "\033[90m",  # grey
            }
            reset = "\033[0m"
            prefix = colour_map.get(level.upper(), "")
            console_msg = f"{prefix}[{self.name}] {message}{reset}"
        else:
            console_msg = f"[{self.name}] {message}"
        # Print to console
        print(console_msg)
        # Append to log file
        try:
            log_path = out_dir / "scanner.log"
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(f"[{self.name}] {message}\n")
        except Exception:
            # Fallback to stderr if logging fails
            try:
                sys.stderr.write(f"[{self.name}] {message}\n")
            except Exception:
                pass

    async def setup(self) -> None:
        """Perform any one‑time initialisation.

        This is run once before any targets are scanned.  Examples include
        verifying external dependencies, spawning background processes, or
        reading large wordlists into memory.
        """
        return None

    async def scan_target(self, target: str, out_dir: Path) -> None:
        """Run the plugin against a single host/target.

        :param target: The IP address or hostname to scan.
        :param out_dir: Directory unique to this target/session where results
                        should be written.  Plugins must create any
                        subdirectories they require.  They must not write
                        outside of this directory.
        """
        raise NotImplementedError

    async def teardown(self) -> None:
        """Perform cleanup once all targets have been scanned."""
        return None


class PluginManager:
    """Loads and manages plugins.

    The manager maintains a registry of plugin classes and instantiates
    them with the provided scan context.  Plugins are loaded lazily to
    minimise startup time.  Additional plugins can be supplied via the
    context's ``plugins`` list as dotted module paths.
    """

    def __init__(self, context: ScanContext) -> None:
        self.context = context
        self._registry: List[Type[BasePlugin]] = []
        self._instances: List[BasePlugin] = []

    def discover_plugins(self) -> None:
        """Discover built‑in plugin classes.

        Built‑in plugins live in the ``recon_tool.plugins`` package.  Any
        subclass of ``BasePlugin`` defined there will be registered.
        """
        import recon_tool.plugins as pkg
        package_path = Path(pkg.__file__).parent
        for file in package_path.glob("*.py"):
            if file.name.startswith("_"):
                continue
            module_name = f"recon_tool.plugins.{file.stem}"
            module = importlib.import_module(module_name)
            self._register_from_module(module)

    def load_additional(self) -> None:
        """Load additional plugins specified in the context.

        Users can supply dotted paths to modules containing plugin subclasses via
        the ``plugins`` option.  Each specified module is imported and any
        subclass of ``BasePlugin`` found will be registered.
        """
        for module_path in self.context.plugins:
            try:
                module = importlib.import_module(module_path)
                self._register_from_module(module)
            except Exception as exc:
                print(f"[PluginManager] Failed to load plugin module {module_path}: {exc}")

    def _register_from_module(self, module: ModuleType) -> None:
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if obj is not BasePlugin and issubclass(obj, BasePlugin):
                self._registry.append(obj)

    def instantiate_plugins(self) -> None:
        """Instantiate all registered plugin classes.
        Each plugin will receive the shared ScanContext instance.
        """
        # Sort classes by their priority attribute before instantiation
        sorted_classes = sorted(self._registry, key=lambda c: getattr(c, "priority", 50))
        for cls in sorted_classes:
            try:
                instance = cls(self.context)
                self._instances.append(instance)
            except Exception as exc:
                print(f"[PluginManager] Failed to instantiate plugin {cls.__name__}: {exc}")

    async def setup(self) -> None:
        for plugin in self._instances:
            await plugin.setup()

    async def teardown(self) -> None:
        for plugin in self._instances:
            await plugin.teardown()

    async def scan_target(self, target: str, out_dir: Path) -> None:
        """Invoke ``scan_target`` on each plugin sequentially for a single host.
        Plugins are awaited in order; if one plugin raises an exception the
        error is printed and subsequent plugins still run.
        """
        for plugin in self._instances:
            try:
                await plugin.scan_target(target, out_dir)
            except Exception as exc:
                print(f"[PluginManager] Error in {plugin.name} while scanning {target}: {exc}")


class ReconRunner:
    """Coordinates scanning of multiple targets using registered plugins."""

    def __init__(self, context: ScanContext) -> None:
        self.context = context
        self.manager = PluginManager(context)

    async def run(self, targets: List[Target]) -> None:
        """Run scans against the provided targets.

        A new subdirectory is created in the context's results directory for
        each target and session.  The current timestamp is used to avoid
        collisions.  Plugins are set up once before scanning begins and
        torn down at the end.
        """
        # Discover and instantiate plugins
        self.manager.discover_plugins()
        self.manager.load_additional()
        self.manager.instantiate_plugins()
        await self.manager.setup()

        timestamp = int(time.time())

        for target in targets:
            for host in target.hosts:
                session_dir = self.context.results_dir / host / f"session_{timestamp}"
                session_dir.mkdir(parents=True, exist_ok=True)
                print(f"[*] Scanning {host}... results will be stored in {session_dir}")
                setattr(self.context, "current_target", host)
                await self.manager.scan_target(host, session_dir)

        await self.manager.teardown()

# Back-compat alias for older imports
ScanRunner = ReconRunner
