"""MCP stdio server wiring: environment -> Runtime -> tools."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool, ToolAnnotations

from .config import load_routers
from .journal import Journal
from .safety import detect_own_identity
from .tools import TOOLS, Registry, Runtime, run_tool
from .transport import EncryptedRouterTransport, RouterTransport

logger = logging.getLogger(__name__)

server: Server = Server("mcp-tplink-router")
_registry: Registry | None = None
_lock = asyncio.Lock()
# Held by the WORKER thread for the whole call: if the asyncio side gives up waiting (timeout),
# the next call still cannot log in (and kick this session) until the running call finishes.
_router_lock = threading.Lock()


def _run_locked(name: str, arguments: dict[str, Any], reg: Registry) -> dict[str, Any]:
    with _router_lock:
        return run_tool(name, arguments, reg)


def registry_from_env() -> Registry:
    journal = Journal()
    routers: dict[str, Runtime] = {}
    for name, cfg in load_routers().items():
        getter = cfg.password_getter()
        if cfg.protocol == "encrypted":
            def factory(cfg=cfg, getter=getter) -> Any:  # noqa: ANN001
                return EncryptedRouterTransport(cfg.host, getter, timeout=cfg.timeout)
        else:
            def factory(cfg=cfg, getter=getter) -> Any:  # noqa: ANN001
                return RouterTransport(cfg.host, getter(), timeout=cfg.timeout)
        host = cfg.host
        routers[name] = Runtime(factory=factory, journal=journal, host=host, name=name, protocol=cfg.protocol,
                                identity=(lambda h=host: detect_own_identity(h)))
    return Registry(routers)


def get_registry() -> Registry:
    global _registry
    if _registry is None:
        _registry = registry_from_env()
    return _registry


def set_registry(reg: Registry | None) -> None:
    global _registry
    _registry = reg


def tool_definitions() -> list[Tool]:
    out = []
    for t in TOOLS.values():
        out.append(Tool(
            name=t.name,
            description=t.description,
            inputSchema=t.schema(),
            annotations=ToolAnnotations(
                readOnlyHint=t.read_only,
                destructiveHint=not t.read_only,
                idempotentHint=t.read_only,
                openWorldHint=False,
            ),
        ))
    return out


@server.list_tools()
async def list_tools() -> list[Tool]:
    return tool_definitions()


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any] | None) -> list[TextContent]:
    # One router session at a time: the router allows a single admin login.
    async with _lock:
        try:
            result = await asyncio.wait_for(asyncio.to_thread(_run_locked, name, arguments or {}, get_registry()),
                                            timeout=float(os.getenv("TPLINK_CALL_TIMEOUT", "180")))
        except asyncio.TimeoutError:
            result = {"error": "tool call timed out; it may still be running in the background",
                      "note": "the next call waits for it to finish; if this was an apply, check router_journal"}
    return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]


def main() -> None:
    from dotenv import load_dotenv

    load_dotenv()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    async def run() -> None:
        logger.info("Starting MCP TP-Link Router server (%d tools)", len(TOOLS))
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(run())


if __name__ == "__main__":
    main()
