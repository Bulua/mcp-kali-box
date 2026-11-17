"""Memory analysis and file rule matching."""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from ..core.executor import CommandRunner
from ..core.paths import resolve_workspace_path


def register_forensic_tools(mcp: MCPServer, runner: CommandRunner) -> None:
    @mcp.tool(name="volatility_analyze")
    def volatility_analyze(image_path: str, plugin: str = "windows.info", timeout: int = 120) -> dict[str, Any]:
        """Run one Volatility 3 plugin against a mounted memory image."""
        image = resolve_workspace_path(image_path, must_exist=True, kind="file")
        if not plugin or not all(part.replace("_", "").isalnum() for part in plugin.split(".")):
            raise ValueError("plugin must be a dotted Volatility plugin name")
        return runner.run(["vol", "-f", str(image), plugin], timeout=timeout)

    @mcp.tool(name="yara_scan")
    def yara_scan(rule_path: str, target_path: str, recursive: bool = False, timeout: int = 120) -> dict[str, Any]:
        """Match a workspace YARA rule against a workspace file or directory."""
        rule = resolve_workspace_path(rule_path, must_exist=True, kind="file")
        target = resolve_workspace_path(target_path, must_exist=True)
        argv = ["yara"]
        if recursive:
            if not target.is_dir():
                raise ValueError("recursive scan requires a directory target")
            argv.append("-r")
        argv.extend([str(rule), str(target)])
        return runner.run(argv, timeout=timeout)
