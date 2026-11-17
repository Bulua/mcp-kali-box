"""Workspace file management and Python execution tools."""

from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from ..core.executor import CommandRunner
from ..core.paths import atomic_write_text, resolve_workspace_path, workspace_root


def register_workspace_tools(mcp: MCPServer, run_command: CommandRunner) -> None:
    """Register generic workspace and Python scripting tools."""

    @mcp.tool(name="workspace_file_manager")
    def workspace_file_manager(
        operation: Literal["list", "read", "write"],
        path: str = ".",
        content: str | None = None,
        recursive: bool = False,
        max_entries: int = 500,
        max_chars: int = 8000,
    ) -> dict[str, Any]:
        """List, inspect, or create text files under /workspace.

        All paths are relative to /workspace and traversal outside the mount is
        rejected. `read` returns at most `max_chars`; `write` stores UTF-8 text
        atomically and replaces an existing file at the same relative path.
        """
        root = workspace_root()
        if operation == "list":
            directory = resolve_workspace_path(path or ".", must_exist=True, kind="directory")
            if not 1 <= max_entries <= 5000:
                raise ValueError("max_entries must be between 1 and 5000")
            iterator = directory.rglob("*") if recursive else directory.iterdir()
            entries: list[dict[str, Any]] = []
            for item in iterator:
                try:
                    resolved = item.resolve()
                    resolved.relative_to(root)
                except (OSError, ValueError):
                    continue
                stat = item.stat()
                entries.append(
                    {
                        "path": str(resolved.relative_to(root)).replace(os.sep, "/"),
                        "type": "directory" if resolved.is_dir() else "file",
                        "size_bytes": stat.st_size,
                        "modified_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                    }
                )
                if len(entries) >= max_entries:
                    break
            entries.sort(key=lambda entry: entry["path"])
            return {
                "success": True,
                "operation": operation,
                "workspace": str(root),
                "entries": entries,
                "truncated": len(entries) == max_entries,
            }

        if operation == "read":
            source = resolve_workspace_path(path, must_exist=True, kind="file")
            if not 1 <= max_chars <= 200000:
                raise ValueError("max_chars must be between 1 and 200000")
            raw = source.read_bytes()
            sample = raw[: min(max_chars * 4, 1024)]
            likely_binary = b"\x00" in sample
            decoded = raw.decode("utf-8", errors="replace")
            text = decoded[:max_chars]
            return {
                "success": True,
                "operation": operation,
                "path": str(source),
                "size_bytes": len(raw),
                "content": text,
                "truncated": len(decoded) > max_chars,
                "likely_binary": likely_binary,
            }

        if content is None:
            raise ValueError("content is required for write")
        destination = resolve_workspace_path(path)
        atomic_write_text(destination, content)
        return {
            "success": True,
            "operation": operation,
            "path": str(destination),
            "size_bytes": len(content.encode("utf-8")),
        }

    @mcp.tool(name="run_python_script")
    def run_python_script(
        script: str,
        filename: str | None = None,
        arguments: list[str] | None = None,
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Save a temporary Python script under /workspace and execute it.

        The script runs with the container Python, isolated-site mode, and
        /workspace as its working directory. Use this for custom decoding,
        proof-of-concept logic, parsing, and report processing. `arguments` are
        passed as argv entries, not through a shell.
        """
        if not script.strip():
            raise ValueError("script must not be empty")
        root = workspace_root()
        script_root = root / ".scripts"
        script_root.mkdir(parents=True, exist_ok=True)
        if filename:
            if not filename.endswith(".py") or "/" in filename or "\\" in filename:
                raise ValueError("filename must be a simple name ending in .py")
            destination = script_root / filename
            destination.resolve().relative_to(root)
        else:
            descriptor, generated = tempfile.mkstemp(prefix="script-", suffix=".py", dir=script_root)
            os.close(descriptor)
            destination = Path(generated)
        atomic_write_text(destination, script)
        argv = [sys.executable, "-I", str(destination), *[str(arg) for arg in arguments or []]]
        result = run_command.run(argv, timeout=timeout, cwd=root)
        result["script_path"] = str(destination)
        return result
