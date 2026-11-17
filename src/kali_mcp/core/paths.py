"""Path confinement and workspace file helpers."""

from __future__ import annotations

import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

_UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9_.-]+")


def workspace_root() -> Path:
    return Path(os.getenv("KALI_MCP_WORKSPACE", "/workspace")).resolve()


def resolve_workspace_path(
    path: str,
    *,
    must_exist: bool = False,
    kind: str = "any",
) -> Path:
    """Resolve a relative path and refuse paths outside /workspace."""
    if not path or not isinstance(path, str):
        raise ValueError("path must be a non-empty relative path")
    if path.startswith("/") or Path(path).is_absolute():
        raise ValueError("absolute paths are not allowed; use a path relative to /workspace")

    root = workspace_root()
    candidate = (root / path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("path escapes /workspace") from exc

    if must_exist and not candidate.exists():
        raise ValueError(f"path does not exist: {path}")
    if kind == "file" and not candidate.is_file():
        raise ValueError(f"path is not a file: {path}")
    if kind == "directory" and not candidate.is_dir():
        raise ValueError(f"path is not a directory: {path}")
    return candidate


def resolve_tool_input_file(path: str) -> Path:
    """Allow mounted files plus installed read-only wordlists."""
    candidate = Path(path).expanduser().resolve()
    if candidate.is_file():
        allowed = candidate.is_relative_to(workspace_root()) or candidate.is_relative_to(
            Path("/usr/share/wordlists").resolve()
        )
        if allowed:
            return candidate
    raise ValueError(
        "tool input file must exist under /workspace or /usr/share/wordlists"
    )


def safe_child(root: Path, relative_path: str) -> Path:
    root = root.resolve()
    candidate = (root / relative_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escapes {root}") from exc
    return candidate


def unique_report_path(tool_name: str) -> Path:
    reports = workspace_root() / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe_name = _UNSAFE_FILENAME.sub("-", tool_name).strip("-") or "tool"
    descriptor, temp_name = tempfile.mkstemp(prefix=f"{timestamp}-{safe_name}-", suffix=".log", dir=reports)
    os.close(descriptor)
    return Path(temp_name)


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise
