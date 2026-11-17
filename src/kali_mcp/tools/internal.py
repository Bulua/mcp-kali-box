"""SMB, LDAP, and simple socket diagnostics."""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from ..core.executor import CommandRunner


def _host(value: str) -> str:
    if not value or not value.strip() or value.strip().startswith("-"):
        raise ValueError("host must be a non-empty value")
    return value.strip()


def register_internal_tools(mcp: MCPServer, runner: CommandRunner) -> None:
    @mcp.tool(name="smb_shares")
    def smb_shares(host: str, timeout: int = 60) -> dict[str, Any]:
        """List anonymously accessible SMB shares on an authorized host."""
        argv = ["smbclient", "-L", f"//{_host(host)}", "-N"]
        return runner.run(argv, timeout=timeout)

    @mcp.tool(name="enum4linux_scan")
    def enum4linux_scan(host: str, timeout: int = 120) -> dict[str, Any]:
        """Enumerate SMB and RPC host information with enum4linux-ng."""
        return runner.run(["enum4linux-ng", "-A", _host(host)], timeout=timeout)

    @mcp.tool(name="tcp_connect")
    def tcp_connect(host: str, port: int, wait_seconds: int = 3, timeout: int = 10) -> dict[str, Any]:
        """Check whether one TCP port accepts a connection using netcat."""
        if not 1 <= port <= 65535 or not 1 <= wait_seconds <= 30:
            raise ValueError("port must be 1-65535 and wait_seconds must be 1-30")
        return runner.run(["nc", "-zv", "-w", str(wait_seconds), _host(host), str(port)], timeout=timeout)

    @mcp.tool(name="socat_connect")
    def socat_connect(host: str, port: int, timeout: int = 10) -> dict[str, Any]:
        """Check a TCP connection using socat with an empty input stream."""
        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        destination = f"TCP:{_host(host)}:{port},connect-timeout=3"
        return runner.run(["socat", "-", destination], timeout=timeout)

    @mcp.tool(name="ldap_query")
    def ldap_query(host: str, base_dn: str, filter_text: str = "(objectClass=*)", scope: Literal["base", "one", "sub"] = "sub", timeout: int = 60) -> dict[str, Any]:
        """Query LDAP with anonymous bind; provide a base DN and search filter."""
        if not base_dn or not filter_text:
            raise ValueError("base_dn and filter_text are required")
        return runner.run(["ldapsearch", "-x", "-LLL", "-H", f"ldap://{_host(host)}", "-b", base_dn, "-s", scope, filter_text], timeout=timeout)

    @mcp.tool(name="impacket_rpcdump")
    def impacket_rpcdump(host: str, timeout: int = 60) -> dict[str, Any]:
        """List RPC endpoints on an authorized Windows host with Impacket."""
        return runner.run(["impacket-rpcdump", _host(host)], timeout=timeout)
