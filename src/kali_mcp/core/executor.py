"""Hardened command execution used by all Kali tool wrappers."""

from __future__ import annotations

import os
import shlex
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .output import limit_output_pair, sanitize_output
from .paths import unique_report_path


class CommandRunner:
    """Run argv commands with timeout, output cleanup, and truncation."""

    def __init__(
        self,
        *,
        workspace: Path | None = None,
        max_output_chars: int | None = None,
        max_timeout: int = 1800,
    ) -> None:
        self.workspace = workspace or Path(os.getenv("KALI_MCP_WORKSPACE", "/workspace")).resolve()
        self.max_output_chars = max_output_chars or int(os.getenv("KALI_MCP_MAX_OUTPUT", "8000"))
        self.max_timeout = max(1, max_timeout)

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 120,
        cwd: Path | None = None,
        env_overrides: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        started = time.monotonic()
        command = [str(item) for item in argv]
        if not command or not command[0] or any(not str(item) for item in command):
            return self._error("InvalidCommand", "The generated command was empty.")

        try:
            timeout = int(timeout)
        except (TypeError, ValueError):
            return self._error("InvalidTimeout", "timeout must be an integer number of seconds.")
        if timeout < 1:
            return self._error("InvalidTimeout", "timeout must be at least 1 second.")
        if timeout > self.max_timeout:
            return self._error(
                "InvalidTimeout",
                f"timeout cannot exceed {self.max_timeout} seconds.",
            )

        environment = os.environ.copy()
        environment.update(
            {
                "NO_COLOR": "1",
                "TERM": "dumb",
                "LC_ALL": "C.UTF-8",
                "LANG": "C.UTF-8",
            }
        )
        if env_overrides:
            environment.update({key: str(value) for key, value in env_overrides.items()})

        try:
            completed = subprocess.run(
                command,
                cwd=None if cwd is None else str(cwd),
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=timeout,
                check=False,
                env=environment,
                stdin=subprocess.DEVNULL,
                **({"start_new_session": True} if os.name == "posix" else {}),
            )
        except subprocess.TimeoutExpired as exc:
            stdout = sanitize_output(getattr(exc, "stdout", None))
            stderr = sanitize_output(getattr(exc, "stderr", None))
            result = self._finish(
                command[0],
                None,
                stdout,
                stderr,
                time.monotonic() - started,
                timeout,
                timed_out=True,
            )
            result["hint"] = (
                "The command timed out. Narrow the target or port range, reduce the wordlist, "
                "increase timeout only when appropriate, then retry. Full partial output was saved."
            )
            return result
        except FileNotFoundError:
            return self._error(
                "ToolUnavailable",
                f"Executable {command[0]!r} is not installed in the container.",
                elapsed=time.monotonic() - started,
            )
        except PermissionError:
            return self._error(
                "PermissionDenied",
                f"The container user is not allowed to run {command[0]!r}.",
                elapsed=time.monotonic() - started,
            )
        except OSError as exc:
            return self._error(
                "ExecutionFailed",
                f"Could not start {command[0]!r}: {exc}",
                elapsed=time.monotonic() - started,
            )

        stdout = sanitize_output(completed.stdout)
        stderr = sanitize_output(completed.stderr)
        result = self._finish(
            command[0],
            completed.returncode,
            stdout,
            stderr,
            time.monotonic() - started,
            timeout,
        )
        if completed.returncode != 0:
            result["hint"] = (
                "Inspect stderr and the exit code. Common causes are invalid target syntax, "
                "missing privileges, an unsupported tool option, or an unreachable target."
            )
        return result

    def _finish(
        self,
        executable: str,
        returncode: int | None,
        stdout: str,
        stderr: str,
        elapsed: float,
        timeout: int,
        *,
        timed_out: bool = False,
    ) -> dict[str, Any]:
        limited_stdout, limited_stderr, truncated = limit_output_pair(
            stdout,
            stderr,
            self.max_output_chars,
        )
        full_output_path: str | None = None
        report_warning: str | None = None

        if truncated or timed_out:
            try:
                report = unique_report_path(executable)
                report.write_text(
                    f"STDOUT\n{stdout}\n\nSTDERR\n{stderr}\n",
                    encoding="utf-8",
                )
                full_output_path = str(report)
            except OSError as exc:
                report_warning = f"Could not save full output to /workspace: {exc}"

        result: dict[str, Any] = {
            "success": returncode == 0 and not timed_out,
            "executable": executable,
            "returncode": returncode,
            "stdout": limited_stdout,
            "stderr": limited_stderr,
            "elapsed_seconds": round(elapsed, 3),
            "timeout_seconds": timeout,
            "timed_out": timed_out,
            "truncated": truncated,
            "full_output_path": full_output_path,
        }
        if timed_out:
            result["error"] = {
                "type": "TimeoutError",
                "message": f"The command exceeded the {timeout} second timeout.",
            }
        if report_warning:
            result["report_warning"] = report_warning
        return result

    def _error(
        self,
        error_type: str,
        message: str,
        *,
        elapsed: float = 0.0,
    ) -> dict[str, Any]:
        return {
            "success": False,
            "error": {"type": error_type, "message": message},
            "stdout": "",
            "stderr": "",
            "elapsed_seconds": round(elapsed, 3),
            "truncated": False,
            "full_output_path": None,
        }


def display_command(argv: Sequence[str]) -> str:
    """Create a user-readable command without ever invoking a shell."""
    return shlex.join([str(item) for item in argv])
