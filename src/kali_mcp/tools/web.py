"""Web application testing and HTTP request tools."""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from ..core.executor import CommandRunner


def register_web_tools(mcp: MCPServer, run_command: CommandRunner) -> None:
    """Register web testing and HTTP utility tools."""

    @mcp.tool(name="directory_scan")
    def directory_scan(
        url: str,
        engine: Literal["gobuster", "ffuf"] = "gobuster",
        dictionary_path: str = "/usr/share/wordlists/dirb/common.txt",
        extensions: str | None = None,
        threads: int = 10,
        follow_redirects: bool = False,
        verify_tls: bool = True,
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Discover common web paths with a lightweight built-in dictionary.

        The default dictionary is the compact DirB common list installed by the
        image. A custom dictionary may be selected from /workspace or
        /usr/share/wordlists. `url` may either be a base URL or contain the
        engine's `FUZZ` marker. Reduce `threads` when testing fragile targets.
        """
        if not url or not url.strip():
            raise ValueError("url must not be empty")
        if not 1 <= threads <= 64:
            raise ValueError("threads must be between 1 and 64")

        from ..core.paths import resolve_tool_input_file

        dictionary = resolve_tool_input_file(dictionary_path)
        if engine == "gobuster":
            target = url if "FUZZ" in url else url.rstrip("/") + "/FUZZ"
            argv = [
                "gobuster",
                "dir",
                "-u",
                target,
                "-w",
                str(dictionary),
                "-t",
                str(threads),
                "-q",
            ]
            if extensions:
                argv.extend(["-x", extensions])
            if follow_redirects:
                argv.append("-r")
            if not verify_tls:
                argv.append("-k")
        else:
            target = url if "FUZZ" in url else url.rstrip("/") + "/FUZZ"
            argv = [
                "ffuf",
                "-s",
                "-u",
                target,
                "-w",
                str(dictionary),
                "-t",
                str(threads),
                "-max-time",
                str(max(1, timeout - 1)),
            ]
            if extensions:
                argv.extend(["-e", extensions])
            if follow_redirects:
                argv.append("-r")
            if not verify_tls:
                argv.append("-k")
        return run_command.run(argv, timeout=timeout)

    @mcp.tool(name="sqlmap_scan")
    def sqlmap_scan(
        url: str,
        action: Literal["fingerprint", "databases", "tables", "dump"] = "fingerprint",
        data: str | None = None,
        cookie: str | None = None,
        method: str | None = None,
        database: str | None = None,
        table: str | None = None,
        level: Literal["1", "2", "3", "4", "5"] = "1",
        risk: Literal["1", "2", "3"] = "1",
        technique: Literal["B", "E", "U", "S", "T", "Q", "BEUST", "BEUSTQ"] | None = None,
        dbms: str | None = None,
        tamper: str | None = None,
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Test a single authorized URL for SQL injection with sqlmap.

        sqlmap always receives `--batch` and `--random-agent`, so it will not
        pause for interactive input. Start with level 1/risk 1. `action`
        selects fingerprinting, database enumeration, table enumeration, or
        dumping a named table. `tables` requires `database`; `dump` requires
        both `database` and `table`.
        """
        if not url or not url.strip():
            raise ValueError("url must not be empty")
        if action in {"tables", "dump"} and not database:
            raise ValueError("database is required for table actions")
        if action == "dump" and not table:
            raise ValueError("table is required for dump")

        argv = [
            "sqlmap",
            "--batch",
            "--random-agent",
            "--flush-session",
            "--retries",
            "2",
            "--timeout",
            "10",
            "--threads",
            "3",
            "--url",
            url,
            "--level",
            level,
            "--risk",
            risk,
        ]
        if data:
            argv.extend(["--data", data])
        if cookie:
            argv.extend(["--cookie", cookie])
        if method:
            argv.extend(["--method", method])
        if technique:
            argv.extend(["--technique", technique])
        if dbms:
            argv.extend(["--dbms", dbms])
        if tamper:
            argv.extend(["--tamper", tamper])
        if action == "databases":
            argv.append("--dbs")
        elif action == "tables":
            argv.extend(["--tables", "-D", database])
        elif action == "dump":
            argv.extend(["--dump", "-D", database, "-T", table])
        return run_command.run(argv, timeout=timeout)

    @mcp.tool(name="nikto_scan")
    def nikto_scan(
        host: str,
        port: int | None = None,
        use_ssl: bool = False,
        tuning: str | None = None,
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Run a non-interactive Nikto web server check on an authorized host.

        `tuning` accepts Nikto tuning codes such as `1,2,3` or `9`. The tool
        automatically sets `-nointeractive` and writes findings to stdout.
        """
        if not host or not host.strip():
            raise ValueError("host must not be empty")
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        argv = ["nikto", "-h", host, "-nointeractive", "-Format", "txt"]
        if port:
            argv.extend(["-p", str(port)])
        if use_ssl:
            argv.append("-ssl")
        if tuning:
            argv.extend(["-Tuning", tuning])
        return run_command.run(argv, timeout=timeout)

    @mcp.tool(name="http_request")
    def http_request(
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: str | None = None,
        cookie: str | None = None,
        follow_redirects: bool = True,
        verify_tls: bool = True,
        include_headers: bool = False,
        username: str | None = None,
        password: str | None = None,
        proxy: str | None = None,
        timeout: int = 60,
    ) -> dict[str, Any]:
        """Send a controlled HTTP request with curl and return sanitized output.

        `headers` is a JSON object of header names to values. `data` is sent as
        the request body without shell interpretation. Set `verify_tls=false`
        only for isolated lab endpoints. Sensitive credentials are not echoed
        in the structured result.
        """
        if not url or not url.strip():
            raise ValueError("url must not be empty")
        if not method.strip():
            raise ValueError("method must not be empty")
        argv = [
            "curl",
            "--silent",
            "--show-error",
            "--compressed",
            "--connect-timeout",
            "10",
            "--max-time",
            str(max(1, timeout - 1)),
            "-X",
            method.upper(),
        ]
        for name, value in (headers or {}).items():
            argv.extend(["-H", f"{name}: {value}"])
        if data is not None:
            argv.extend(["--data", data])
        if cookie:
            argv.extend(["--cookie", cookie])
        if follow_redirects:
            argv.append("--location")
        if not verify_tls:
            argv.append("--insecure")
        if include_headers:
            argv.append("--include")
        if username is not None and password is not None:
            argv.extend(["--user", f"{username}:{password}"])
        elif username is not None or password is not None:
            raise ValueError("username and password must be supplied together")
        if proxy:
            argv.extend(["--proxy", proxy])
        argv.append(url)
        return run_command.run(argv, timeout=timeout)
