"""Information collection and network reconnaissance tools."""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from ..core.executor import CommandRunner


def _required_target(value: str, label: str = "target") -> None:
    if not value or not value.strip():
        raise ValueError(f"{label} must not be empty")
    if value.strip().startswith("-"):
        raise ValueError(f"{label} must be a value, not a command-line option")


def register_recon_tools(mcp: MCPServer, run_command: CommandRunner) -> None:
    """Register network and service reconnaissance tools."""

    @mcp.tool(name="nmap_scan")
    def nmap_scan(
        target: str,
        ports: str | None = None,
        scan_type: Literal["tcp_connect", "syn", "udp"] = "tcp_connect",
        service_version: bool = True,
        os_detection: bool = False,
        top_ports: int | None = None,
        scripts: str | None = None,
        script_args: dict[str, str] | None = None,
        timing_template: Literal["0", "1", "2", "3", "4", "5"] = "3",
        max_rate: int = 1000,
        host_timeout: int | None = None,
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Run a bounded Nmap scan against an authorized target.

        Use `scan_type="tcp_connect"` for broad compatibility, `scan_type="syn"`
        for a faster TCP scan when the container has NET_RAW, and
        `scan_type="udp"` for a slower UDP probe. `ports` accepts Nmap syntax
        such as `80,443` or `1-1000`. Set `scripts` to a comma-separated Nmap
        script name or category list. Results are truncated to protect the
        caller context; full oversized output is saved under /workspace/reports.
        """
        _required_target(target)
        argv = ["nmap", f"-T{timing_template}", f"--max-rate={max(1, max_rate)}", "--open"]
        if scan_type == "syn":
            argv.append("-sS")
        elif scan_type == "udp":
            argv.append("-sU")
        else:
            argv.append("-sT")
        if service_version:
            argv.append("-sV")
        if os_detection:
            argv.append("-O")
        if ports:
            argv.extend(["-p", ports])
        if top_ports is not None:
            argv.extend(["--top-ports", str(max(1, top_ports))])
        if scripts:
            argv.extend(["--script", scripts])
        if script_args:
            joined = ",".join(f"{key}={value}" for key, value in script_args.items())
            argv.extend(["--script-args", joined])
        if host_timeout is not None:
            argv.extend(["--host-timeout", f"{max(1, host_timeout)}s"])
        argv.append(target)
        return run_command.run(argv, timeout=timeout)

    @mcp.tool(name="whatweb_scan")
    def whatweb_scan(
        url: str,
        aggression: Literal["1", "2", "3", "4"] = "1",
        user_agent: str | None = None,
        follow_redirect: bool = False,
        proxy: str | None = None,
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Identify a website's fingerprint and common technology stack.

        Keep `aggression` at 1 for passive, low-impact checks. Values 2-4 issue
        progressively more requests and should only be used on authorized
        systems. `proxy` accepts WhatWeb proxy syntax such as
        `http://127.0.0.1:8080`.
        """
        _required_target(url, "url")
        argv = [
            "whatweb",
            "--no-errors",
            "--aggression",
            aggression,
            "--follow-redirect",
            "always" if follow_redirect else "never",
        ]
        if user_agent:
            argv.extend(["--user-agent", user_agent])
        if proxy:
            argv.extend(["--proxy", proxy])
        argv.append(url)
        return run_command.run(argv, timeout=timeout)

    @mcp.tool(name="whois_lookup")
    def whois_lookup(
        query: str,
        server: str | None = None,
        timeout: int = 60,
    ) -> dict[str, Any]:
        """Query WHOIS registration data for a domain, IP, or ASN.

        `server` optionally selects a specific WHOIS server, for example
        `whois.iana.org`.
        """
        _required_target(query, "query")
        argv = ["whois"]
        if server:
            _required_target(server, "server")
            argv.extend(["--host", server])
        argv.append(query)
        return run_command.run(argv, timeout=timeout)

    @mcp.tool(name="dns_lookup")
    def dns_lookup(
        domain: str,
        record_type: str = "A",
        server: str | None = None,
        short_answer: bool = False,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Resolve a DNS record using the container's resolver or a custom server.

        Common `record_type` values include A, AAAA, CNAME, MX, NS, TXT, SOA,
        PTR, SRV, AXFR, and ANY. `server` must be an IP address and is passed
        to dig as `@server`.
        """
        _required_target(domain, "domain")
        argv = ["dig"]
        if server:
            _required_target(server, "server")
            argv.append(f"@{server}")
        argv.extend([domain, record_type.strip().upper() or "A"])
        if short_answer:
            argv.append("+short")
        else:
            argv.extend(["+noall", "+answer", "+authority", "+additional"])
        return run_command.run(argv, timeout=timeout)
