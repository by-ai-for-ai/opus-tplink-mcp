"""MCP server for the TP-Link Archer BE9300 (LuCI JSON API, BE-series firmware).

Run ``mcp-tplink-router`` (stdio).  Configure with TPLINK_HOST / TPLINK_PASSWORD.
"""

from __future__ import annotations

from typing import Any

__version__ = "0.2.0"


def main() -> None:
    from .server import main as _main

    _main()


def __getattr__(name: str) -> Any:  # lazy re-exports keep `import mcp_tplink_router` light
    if name in ("RouterTransport", "RouterError"):
        from . import transport

        return getattr(transport, name)
    raise AttributeError(name)


__all__ = ["main", "RouterTransport", "RouterError", "__version__"]
