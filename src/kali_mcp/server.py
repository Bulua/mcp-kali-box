"""Application factory and transport entrypoint for Kali MCP Server."""

from __future__ import annotations

import logging
import os
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
import hmac

import uvicorn
from mcp.server.mcpserver import MCPServer
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from .core.executor import CommandRunner
from .tools.binary import register_binary_tools
from .tools.credentials import register_credential_tools
from .tools.discovery import register_discovery_tools
from .tools.forensics import register_forensic_tools
from .tools.internal import register_internal_tools
from .tools.recon import register_recon_tools
from .tools.web import register_web_tools
from .tools.workspace import register_workspace_tools


_TOKEN_PATTERN = re.compile(r"[0-9a-fA-F]{64}")


class BearerTokenMiddleware:
    """Require a static bearer token for every non-health HTTP route."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        self.app = app
        self.token = token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if scope.get("path") == "/health":
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        authorization = headers.get(b"authorization", b"").decode("latin-1")
        scheme, _, credential = authorization.partition(" ")
        supplied = credential.strip().encode("utf-8")
        expected = self.token.encode("utf-8")
        valid = (
            scheme.lower() == "bearer"
            and bool(supplied)
            and hmac.compare_digest(supplied, expected)
        )
        if not valid:
            response = JSONResponse(
                {"success": False, "error": {"type": "Unauthorized", "message": "A valid bearer token is required."}},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer", "Cache-Control": "no-store"},
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


def _required_api_token() -> str:
    token = os.getenv("KALI_MCP_API_TOKEN", "").strip()
    if not token:
        raise RuntimeError(
            "KALI_MCP_API_TOKEN is required. Generate a 64-character hex token."
        )
    if not _TOKEN_PATTERN.fullmatch(token):
        raise RuntimeError("KALI_MCP_API_TOKEN must be exactly 64 hexadecimal characters.")
    return token


def _authenticated_app(routes: list[Route], streamable_app: Starlette | None = None) -> Starlette:
    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        if streamable_app is None:
            yield
        else:
            # Only streamable HTTP owns a session-manager lifespan. SSE
            # sessions initialize when each /sse connection is established.
            async with streamable_app.router.lifespan_context(streamable_app):
                yield

    return Starlette(
        routes=[Route("/health", health, methods=["GET"]), *routes],
        lifespan=lifespan,
        middleware=[Middleware(BearerTokenMiddleware, token=_required_api_token())],
    )


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
    register_discovery_tools(mcp, runner)
    register_internal_tools(mcp, runner)
    register_forensic_tools(mcp, runner)
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

    return _authenticated_app(
        [*sse_app.router.routes, *streamable_app.router.routes],
        streamable_app=streamable_app,
    )


def create_sse_transport_app() -> Starlette:
    """Expose authenticated legacy SSE transport."""
    mcp = create_server()
    host = os.getenv("KALI_MCP_HOST", "0.0.0.0")
    sse_app = mcp.sse_app(
        sse_path="/sse",
        message_path="/messages/",
        host=host,
    )
    return _authenticated_app(list(sse_app.router.routes))


def create_streamable_http_transport_app() -> Starlette:
    """Expose authenticated streamable HTTP transport."""
    mcp = create_server()
    host = os.getenv("KALI_MCP_HOST", "0.0.0.0")
    streamable_app = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=False,
        host=host,
    )
    return _authenticated_app(list(streamable_app.router.routes), streamable_app=streamable_app)


def main() -> None:
    """Start SSE, streamable HTTP, or both according to configuration."""
    logging.basicConfig(
        level=os.getenv("KALI_MCP_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    transport = os.getenv("KALI_MCP_TRANSPORT", "dual").strip().lower() or "dual"
    host = os.getenv("KALI_MCP_HOST", "0.0.0.0")
    port = int(os.getenv("KALI_MCP_PORT", "8000"))

    if transport == "dual":
        app = create_dual_transport_app()
    elif transport == "sse":
        app = create_sse_transport_app()
    elif transport in {"streamable-http", "http"}:
        app = create_streamable_http_transport_app()
    else:
        raise ValueError(
            "KALI_MCP_TRANSPORT must be one of: dual, sse, streamable-http"
        )
        return

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=os.getenv("KALI_MCP_LOG_LEVEL", "info").lower(),
    )
