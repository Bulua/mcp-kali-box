"""Domain, HTTP, template, and TLS discovery."""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from ..core.executor import CommandRunner
from ..core.paths import resolve_tool_input_file


def _value(text: str, label: str) -> str:
    if not text or not text.strip() or text.strip().startswith("-"):
        raise ValueError(f"{label} must be a non-empty value")
    return text.strip()


def register_discovery_tools(mcp: MCPServer, runner: CommandRunner) -> None:
    @mcp.tool(name="subdomain_discover")
    def subdomain_discover(domain: str, engine: Literal["subfinder", "amass"] = "subfinder", timeout: int = 120) -> dict[str, Any]:
        """Discover subdomains of an authorized domain. Amass uses passive mode."""
        domain = _value(domain, "domain")
        argv = ["subfinder", "-silent", "-d", domain] if engine == "subfinder" else ["amass", "enum", "-passive", "-d", domain]
        return runner.run(argv, timeout=timeout)

    @mcp.tool(name="http_probe")
    def http_probe(target: str | None = None, targets_file: str | None = None, threads: int = 10, timeout: int = 120) -> dict[str, Any]:
        """Probe one URL/host or a workspace file with ProjectDiscovery HTTPX."""
        if bool(target) == bool(targets_file):
            raise ValueError("provide exactly one of target or targets_file")
        if not 1 <= threads <= 50:
            raise ValueError("threads must be between 1 and 50")
        argv = ["httpx-toolkit", "-silent", "-status-code", "-title", "-tech-detect", "-threads", str(threads)]
        argv.extend(["-u", _value(target, "target")] if target else ["-l", str(resolve_tool_input_file(targets_file))])
        return runner.run(argv, timeout=timeout)

    @mcp.tool(name="nuclei_scan")
    def nuclei_scan(target: str | None = None, targets_file: str | None = None, severity: str | None = None, rate_limit: int = 10, timeout: int = 120) -> dict[str, Any]:
        """Run installed Nuclei templates against an authorized target. Templates may require an update."""
        if bool(target) == bool(targets_file):
            raise ValueError("provide exactly one of target or targets_file")
        if not 1 <= rate_limit <= 100:
            raise ValueError("rate_limit must be between 1 and 100")
        argv = ["nuclei", "-silent", "-no-color", "-rate-limit", str(rate_limit)]
        argv.extend(["-u", _value(target, "target")] if target else ["-l", str(resolve_tool_input_file(targets_file))])
        if severity:
            allowed = {"info", "low", "medium", "high", "critical"}
            items = {part.strip().lower() for part in severity.split(",")}
            if not items or not items <= allowed:
                raise ValueError("severity must contain info, low, medium, high, or critical")
            argv.extend(["-severity", ",".join(sorted(items))])
        return runner.run(argv, timeout=timeout)

    @mcp.tool(name="feroxbuster_scan")
    def feroxbuster_scan(url: str, dictionary_path: str = "/usr/share/wordlists/dirb/common.txt", depth: int = 2, threads: int = 10, timeout: int = 120) -> dict[str, Any]:
        """Recursively discover web paths with bounded depth and concurrency."""
        if not 0 <= depth <= 5 or not 1 <= threads <= 50:
            raise ValueError("depth must be 0-5 and threads must be 1-50")
        argv = ["feroxbuster", "--quiet", "--no-state", "--url", _value(url, "url"), "--wordlist", str(resolve_tool_input_file(dictionary_path)), "--depth", str(depth), "--threads", str(threads)]
        return runner.run(argv, timeout=timeout)

    @mcp.tool(name="tls_scan")
    def tls_scan(host: str, port: int = 443, timeout: int = 120) -> dict[str, Any]:
        """Inspect a server's TLS versions, ciphers, and certificate with sslscan."""
        host = _value(host, "host")
        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        return runner.run(["sslscan", "--no-colour", f"{host}:{port}"], timeout=timeout)

    @mcp.tool(name="testssl_scan")
    def testssl_scan(host: str, port: int = 443, timeout: int = 120) -> dict[str, Any]:
        """Run a broader noninteractive TLS check with testssl.sh."""
        host = _value(host, "host")
        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        return runner.run(["testssl", "--quiet", "--warnings", "off", f"{host}:{port}"], timeout=timeout)
