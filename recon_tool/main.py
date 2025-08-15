"""
recon_tool.main
---------------

Entry point for the reconnaissance framework.

Features:
- Accepts single/multiple targets (CLI or --targets-file).
- Exposes port-scope controls (TCP/UDP).
- Passes directory brute options (wordlist).
- Wires up SQLi run-all-and-aggregate controls.
- Supports rate limiting, auto-confirm, optional patterns/hints paths.
- Runs the ScanRunner asynchronously across all targets.

Run examples:
    # Basic
    python3 -m recon_tool.main 10.10.10.10 --auto-confirm

    # With wordlist and web-only TCP preset, run-all SQLi
    python3 -m recon_tool.main 10.10.10.10 \
        --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
        --tcp-ports top100 --auto-confirm --rate 5 --sqli-mode balanced

    # Multiple targets from file
    python3 -m recon_tool.main --targets-file targets.txt --auto-confirm
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import List

from recon_tool.core import ScanContext, ReconRunner, Target # Note: ReconRunner + Target


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="recon_tool",
        description="Modular reconnaissance and SQLi automation (run-all-and-aggregate).",
    )

    # Targets
    parser.add_argument(
        "targets",
        nargs="*",
        help="Target(s): IP/host/domain (space-separated). You may also use --targets-file.",
    )
    parser.add_argument(
        "--targets-file",
        help="Path to a file with one target per line.",
        default=None,
    )

    # Port scanning scope
    parser.add_argument(
        "--tcp-ports",
        default="top100",
        help="TCP ports: preset (top100, top1000, web-only, all) or comma-separated list (e.g., 80,443,22).",
    )
    parser.add_argument(
        "--udp-ports",
        default=None,
        help="UDP ports: preset (top100, top1000) or comma-separated list.",
    )

    # Web enumeration
    parser.add_argument(
        "--wordlist",
        default=None,
        help="Wordlist for directory brute forcing (e.g., DirBuster/Feroxbuster lists).",
    )

    # Global behavior / UX
    parser.add_argument(
        "--auto-confirm",
        action="store_true",
        help="Skip confirmation prompts for invasive tests (e.g., SQLi/LFI).",
    )
    parser.add_argument(
        "--rate",
        type=int,
        default=5,
        help="Global request rate target (req/sec) used by HTTP modules.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colorized console output.",
    )

    # Optional pattern/highlight & hints (if your plugins support them)
    parser.add_argument(
        "--patterns",
        default=None,
        help="Path to patterns.toml (global & per-scan regex highlights).",
    )
    parser.add_argument(
        "--hints",
        default=None,
        help="Path to hints.yaml (per-service suggested manual commands).",
    )

    # LFI / traversal
    parser.add_argument(
        "--lfi-aggressive",
        action="store_true",
        help="Enable aggressive LFI techniques (e.g., log poisoning). OFF by default.",
    )

    # SQLi engine (run-all-and-aggregate)
    parser.add_argument(
        "--sqli-run-all",
        action="store_true",
        default=True,
        help="Run every SQLi technique and aggregate findings (default: on).",
    )
    parser.add_argument(
        "--sqli-mode",
        choices=["fast", "balanced", "deep"],
        default="balanced",
        help="Intensity of SQLi testing: fast | balanced | deep.",
    )
    parser.add_argument(
        "--sqli-max-per-endpoint",
        type=int,
        default=12,
        help="Max payloads per technique per endpoint (caps noise).",
    )
    parser.add_argument(
        "--sqli-timeout",
        type=int,
        default=10,
        help="Per-request HTTP timeout for SQLi checks (seconds).",
    )
    parser.add_argument(
        "--sqli-confirmations",
        type=int,
        default=2,
        help="Confirmations for time-based hits (e.g., require 2/3).",
    )
    parser.add_argument(
        "--sqli-oob-domain",
        default=None,
        help="(Opt-in) Collaborator domain for OOB tests (advanced).",
    )

    return parser.parse_args()


def _load_targets(args: argparse.Namespace) -> List[str]:
    targets: List[str] = []
    if args.targets:
        targets.extend(args.targets)
    if args.targets_file:
        p = Path(args.targets_file)
        if not p.exists():
            print(f"[!] Targets file not found: {p}", file=sys.stderr)
            sys.exit(2)
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    # De-dup while preserving order
    seen, unique = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


def main() -> None:
    args = parse_args()
    raw_targets = _load_targets(args)
    if not raw_targets:
        print("[!] No targets provided. Specify positional targets or use --targets-file.", file=sys.stderr)
        sys.exit(2)

    # Everything plugins might need goes into additional_options
    additional = {
        # common
        "auto_confirm": bool(args.auto_confirm),
        "rate": int(args.rate),
        "no_color": bool(args.no_color),
        # scanning scope
        "tcp_ports": args.tcp_ports,
        "udp_ports": args.udp_ports,
        # wordlist & config files
        "wordlist": args.wordlist,
        "patterns_file": args.patterns,
        "hints_file": args.hints,
        # lfi/traversal
        "lfi_aggressive": bool(args.lfi_aggressive),
        # SQLi run-all engine
        "sqli_run_all": bool(args.sqli_run_all),
        "sqli_mode": args.sqli_mode,
        "sqli_max_per_endpoint": int(args.sqli_max_per_endpoint),
        "sqli_timeout": int(args.sqli_timeout),
        "sqli_confirmations": int(args.sqli_confirmations),
        "sqli_oob_domain": args.sqli_oob_domain,
    }

    ctx = ScanContext(
    wordlist=args.wordlist,
    patterns_file=args.patterns,
    hints_file=args.hints,
    tcp_ports=args.tcp_ports,
    udp_ports=args.udp_ports,
    no_color=bool(args.no_color),
    additional_options=additional,   # keep everything else available too
    )

    runner = ReconRunner(ctx)
    targets = [Target(t) for t in raw_targets]
    try:
        asyncio.run(runner.run(targets))
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
