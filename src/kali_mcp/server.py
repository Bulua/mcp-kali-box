"""Application factory and transport entrypoint for Kali MCP Server."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

import uvicorn
from mcp.server.mcpserver import MCPServer
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from .core.executor import CommandRunner
from .tools.binary import register_binary_tools
from .tools.credentials import register_credential_tools
from .tools.recon import register_recon_tools
from .tools.web import register_web_tools
from .tools.workspace import register_workspace_tools


def create_server() -> MCPServer:
    """Build the MCP server and register all tool groups."""
    mcp = MCPServer(
        name="Kali MCP Server",
        description=(
            "Containerized Kali Linux tools for authorized penetration tests, "
            "CTF work, and defensive security analysis."
        ),
        instructions=(
            "Only use these tools against systems you are explicitly authorized "
            "to test. Prefer the narrowest target range, lowest aggression, and "
            "shortest practical timeout. Oversized command output is written "
            "under /workspace/reports."
        ),
    )
    runner = CommandRunner()
    register_recon_tools(mcp, runner)
    register_web_tools(mcp, runner)
    register_credential_tools(mcp, runner)
    register_binary_tools(mcp, runner)
    register_workspace_tools(mcp, runner)
    return mcp


async def health(request: Request) -> JSONResponse:
    """Return a lightweight HTTP health response."""
    return JSONResponse({"status": "ok", "service": "kali-mcp"})


def create_dual_transport_app() -> Starlette:
    """Expose legacy SSE and current streamable HTTP on one uvicorn port."""
    mcp = create_server()
    host = os.getenv("KALI_MCP_HOST", "0.0.0.0")
    sse_app = mcp.sse_app(
        sse_path="/sse",
        message_path="/messages/",
        host=host,
    )
    streamable_app = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=False,
        host=host,
    )

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        # Only streamable HTTP owns a session-manager lifespan. SSE sessions
        # initialize when each /sse connection is established.
        async with streamable_app.router.lifespan_context(streamable_app):
            yield

    return Starlette(
        routes=[
            Route("/health", health, methods=["GET"]),
            *sse_app.router.routes,
            *streamable_app.router.routes,
        ],
        lifespan=lifespan,
    )


def main() -> None:
    """Start SSE, streamable HTTP, or both according to configuration."""
    logging.basicConfig(
        level=os.getenv("KALI_MCP_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    transport = os.getenv("KALI_MCP_TRANSPORT", "dual").lower()
    host = os.getenv("KALI_MCP_HOST", "0.0.0.0")
    port = int(os.getenv("KALI_MCP_PORT", "8000"))

    if transport == "dual":
        uvicorn.run(
            create_dual_transport_app(),
            host=host,
            port=port,
            log_level=os.getenv("KALI_MCP_LOG_LEVEL", "info").lower(),
        )
        return

    mcp = create_server()
    if transport == "sse":
        mcp.run(transport="sse", host=host, port=port)
    elif transport in {"streamable-http", "http"}:
        mcp.run(
            transport="streamable-http",
            host=host,
            port=port,
            streamable_http_path="/mcp",
        )
    else:
        raise ValueError(
            "KALI_MCP_TRANSPORT must be one of: dual, sse, streamable-http"
        )
