"""MCP stdio server wiring: environment -> Runtime -> tools."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool, ToolAnnotations

from .config import load_routers
from .extender_transport import ExtenderTransport, HardenedTransport
from .journal import Journal
from .safety import detect_own_identity
from .tools import TOOLS, Registry, Runtime, described, offered, run_tool
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
    try:
        sealed = journal.migrate()  # older versions stored device state (incl. Wi-Fi passwords) as plain text
        if sealed:
            print(f"opus-tplink-mcp: encrypted {sealed} journal record(s) left in plain text by an older version",
                  file=sys.stderr)
    except (OSError, ValueError) as exc:  # ValueError: a damaged journal.key - start anyway, say why
        print(f"opus-tplink-mcp: could not encrypt the old journal ({exc}); it still holds plain text",
              file=sys.stderr)
    routers: dict[str, Runtime] = {}
    for name, cfg in load_routers().items():
        getter = cfg.password_getter()
        if cfg.protocol == "encrypted":
            def factory(cfg=cfg, getter=getter) -> Any:  # noqa: ANN001
                return EncryptedRouterTransport(cfg.host, getter, timeout=cfg.timeout)
        elif cfg.protocol == "extender":
            def factory(cfg=cfg, getter=getter) -> Any:  # noqa: ANN001
                return ExtenderTransport(cfg.host, getter, timeout=cfg.timeout)
        elif cfg.protocol == "encrypted-v2":
            def factory(cfg=cfg, getter=getter) -> Any:  # noqa: ANN001
                return HardenedTransport(cfg.host, getter, timeout=cfg.timeout)
        else:
            def factory(cfg=cfg, getter=getter) -> Any:  # noqa: ANN001
                return RouterTransport(cfg.host, getter(), timeout=cfg.timeout)
        host = cfg.host
        routers[name] = Runtime(factory=factory, journal=journal, host=host, name=name, protocol=cfg.protocol,
                                kind=cfg.kind,
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
        if not offered(t.name):
            continue
        out.append(Tool(
            name=t.name,
            description=described(t),
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


CONFIG_ENV = Path("~/.config/opus-tplink-mcp/.env")


def load_env_file(environ: dict[str, str] | None = None) -> Path | None:
    """Load the first config file found; values already in the environment (e.g. the MCP client config) win.

    Order: TPLINK_ENV_FILE (explicit path), ~/.config/opus-tplink-mcp/.env, ./.env.  (A bare load_dotenv()
    searches from the installed package's folder, so a user's file was never found after pip/uvx installs.)
    """
    from dotenv import load_dotenv

    env = os.environ if environ is None else environ
    for cand in (env.get("TPLINK_ENV_FILE"), str(CONFIG_ENV), ".env"):
        if not cand:
            continue
        path = Path(cand).expanduser()
        if path.is_file():
            load_dotenv(path, override=False)
            return path
    return None


def main() -> None:
    # Subcommands for people; no argument = the MCP stdio server (what AI clients launch).
    if len(sys.argv) > 1 and sys.argv[1] in ("watch", "viewer", "setup", "report"):
        cmd, rest = sys.argv[1], sys.argv[2:]
        load_env_file()
        if cmd == "setup":
            from .reporting import interactive_setup

            raise SystemExit(interactive_setup())
        if cmd == "report":
            from .reporting import dry_run_main

            raise SystemExit(dry_run_main(rest))
        if cmd == "watch":
            from .watch import main as watch_main

            raise SystemExit(watch_main(rest))
        from .viewer import main as viewer_main

        raise SystemExit(viewer_main(rest))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    loaded = load_env_file()
    logger.info("configuration: %s", loaded or "environment only (no .env file found)")
    from .reporting import status_line

    # stderr only (stdout is the MCP JSON-RPC stream); never in a tool reply, so an AI cannot "consent"
    logger.info("%s", status_line())

    async def run() -> None:
        logger.info("Starting MCP TP-Link Router server (%d tools)", len(TOOLS))
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(run())


if __name__ == "__main__":
    main()
