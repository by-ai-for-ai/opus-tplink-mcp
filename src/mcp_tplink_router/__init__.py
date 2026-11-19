"""MCP server for the TP-Link Archer BE9300 (LuCI JSON API, BE-series firmware).

Run ``mcp-tplink-router`` (stdio).  Configure with TPLINK_HOST / TPLINK_PASSWORD.
"""

from __future__ import annotations

from typing import Any

try:
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("opus-tplink-mcp")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0+source"


def main() -> None:
    from .server import main as _main

    _main()


def __getattr__(name: str) -> Any:  # lazy re-exports keep `import mcp_tplink_router` light
    if name in ("RouterTransport", "RouterError"):
        from . import transport

        return getattr(transport, name)
    raise AttributeError(name)


__all__ = ["main", "RouterTransport", "RouterError", "__version__"]
