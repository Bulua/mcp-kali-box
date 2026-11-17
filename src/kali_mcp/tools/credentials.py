"""Credential testing and hash analysis tools."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from ..core.executor import CommandRunner
from ..core.paths import atomic_write_text, resolve_tool_input_file, workspace_root


def _hash_file(hash_text: str | None, hash_file: str | None, prefix: str) -> Path:
    if bool(hash_text) == bool(hash_file):
        raise ValueError("provide exactly one of hash_text or hash_file")
    if hash_file:
        return resolve_tool_input_file(hash_file)
    root = workspace_root() / ".hashes"
    root.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f"{prefix}-", suffix=".txt", dir=root)
    os.close(descriptor)
    path = Path(name)
    atomic_write_text(path, (hash_text or "").strip() + "\n")
    return path


def register_credential_tools(mcp: MCPServer, run_command: CommandRunner) -> None:
    """Register credential testing and hash-cracking tools."""

    @mcp.tool(name="hydra_brute_force")
    def hydra_brute_force(
        target: str,
        service: str,
        username: str | None = None,
        username_file: str | None = None,
        password: str | None = None,
        password_file: str | None = None,
        port: int | None = None,
        threads: int = 4,
        wait_seconds: int = 5,
        use_ssl: bool = False,
        stop_on_success: bool = False,
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Run Hydra against one authorized network service.

        Provide either `username` or `username_file`, and either `password` or
        `password_file`. Files must be under /workspace or
        /usr/share/wordlists. Hydra automatically receives `-I` to ignore old
        restore prompts and is run non-interactively.
        """
        if not target or not target.strip():
            raise ValueError("target must not be empty")
        if not service or not service.strip() or service.strip().startswith("-"):
            raise ValueError("service must be a valid Hydra module name")
        if bool(username) == bool(username_file):
            raise ValueError("provide exactly one of username or username_file")
        if bool(password) == bool(password_file):
            raise ValueError("provide exactly one of password or password_file")
        if not 1 <= threads <= 32:
            raise ValueError("threads must be between 1 and 32")
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")

        argv = ["hydra", "-I", "-t", str(threads), "-W", str(max(1, wait_seconds))]
        if username:
            argv.extend(["-l", username])
        else:
            argv.extend(["-L", str(resolve_tool_input_file(username_file or ""))])
        if password:
            argv.extend(["-p", password])
        else:
            argv.extend(["-P", str(resolve_tool_input_file(password_file or ""))])
        if port:
            argv.extend(["-s", str(port)])
        if use_ssl:
            argv.append("-S")
        if stop_on_success:
            argv.append("-f")
        argv.extend([target, service])
        return run_command.run(argv, timeout=timeout)

    @mcp.tool(name="john_crack_hash")
    def john_crack_hash(
        hash_text: str | None = None,
        hash_file: str | None = None,
        hash_format: str | None = None,
        wordlist_path: str = "/usr/share/wordlists/dirb/common.txt",
        show_previously_cracked: bool = False,
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Crack a supported hash or password file with John the Ripper.

        Provide exactly one of `hash_text` or `hash_file`. `hash_format` is the
        John format name (for example `raw-md5`, `sha512crypt`, or `NT`).
        Cracked results are also written to the container-local John pot file.
        """
        source = _hash_file(hash_text, hash_file, "john")
        wordlist = resolve_tool_input_file(wordlist_path)
        root = workspace_root()
        root.mkdir(parents=True, exist_ok=True)
        (root / ".john").mkdir(parents=True, exist_ok=True)
        argv = ["john", f"--pot={root / '.john' / 'kali-mcp.pot'}"]
        if hash_format:
            argv.append(f"--format={hash_format}")
        if show_previously_cracked:
            argv.extend(["--show", str(source)])
        else:
            argv.extend(["--wordlist", str(wordlist), str(source)])
        return run_command.run(argv, timeout=timeout)

    @mcp.tool(name="hashcat_identify")
    def hashcat_identify(
        hash_text: str | None = None,
        hash_file: str | None = None,
        timeout: int = 60,
    ) -> dict[str, Any]:
        """Identify likely Hashcat modes for a hash or mounted hash file.

        Provide exactly one of `hash_text` or `hash_file`. This runs Hashcat's
        read-only `--identify` mode and does not attempt a crack.
        """
        source = _hash_file(hash_text, hash_file, "hashcat-identify")
        return run_command.run(["hashcat", "--identify", str(source)], timeout=timeout)

    @mcp.tool(name="hashcat_crack_hash")
    def hashcat_crack_hash(
        hash_mode: int,
        hash_text: str | None = None,
        hash_file: str | None = None,
        wordlist_path: str = "/usr/share/wordlists/dirb/common.txt",
        workload_profile: Literal["1", "2", "3", "4"] = "1",
        optimized_kernel: bool = False,
        show_already_cracked: bool = False,
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Crack a hash with Hashcat using a numeric hash mode.

        `hash_mode` is Hashcat's `-m` mode number. The container provides CPU
        OpenCL support, but performance is modest and GPU passthrough is not
        configured. `optimized_kernel` maps to `-O` and can reject passwords
        longer than the optimized kernel permits.
        """
        if hash_mode < 0:
            raise ValueError("hash_mode must be a non-negative Hashcat mode number")
        source = _hash_file(hash_text, hash_file, "hashcat")
        wordlist = resolve_tool_input_file(wordlist_path)
        root = workspace_root()
        root.mkdir(parents=True, exist_ok=True)
        (root / ".hashcat").mkdir(parents=True, exist_ok=True)
        argv = [
            "hashcat",
            "--quiet",
            "-m",
            str(hash_mode),
            "-w",
            workload_profile,
            "--potfile-path",
            str(root / ".hashcat" / "kali-mcp.pot"),
        ]
        if optimized_kernel:
            argv.append("-O")
        if show_already_cracked:
            argv.extend(["--show", str(source)])
        else:
            argv.extend([str(source), str(wordlist)])
        return run_command.run(argv, timeout=timeout)
