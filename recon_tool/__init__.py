"""
Recon Tool Package
===================

This package contains the core logic for the custom reconnaissance tool.  The
modules found here implement a modular scanning architecture inspired by, but
distinct from, the AutoRecon project.  All of the code in this package was
written from scratch for this task; no code has been copied from
AutoRecon or any other third‑party tool.  The overall design focuses on
extensibility via a plugin system, asynchronous operations for performance and
responsiveness, and clear separation of duties between scanning,
analysis and reporting.

The main entry point for running the tool is ``recon_tool.main.main``.  See
``recon_tool/README.md`` for usage examples and further documentation.
"""

__all__ = [
    "core",
    "plugins",
    "main",
]