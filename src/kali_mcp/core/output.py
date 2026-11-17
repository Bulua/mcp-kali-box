"""Output normalization helpers shared by every command tool."""

from __future__ import annotations

import re
from dataclasses import dataclass

_ANSI_ESCAPE = re.compile(
    r"(?:\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)))",
    flags=re.IGNORECASE,
)
_PROGRESS_LINE = re.compile(
    r"^(?:"
    r"[-\\|/]+"
    r"|\[[=>#*\-\s]*\]\s*\d+(?:\.\d+)?%"
    r"|::\s*Progress:.*"
    r"|\d+(?:\.\d+)?%\s*(?:complete|done|processed)?"
    r")\s*$",
    flags=re.IGNORECASE,
)


@dataclass(frozen=True)
class LimitedText:
    text: str
    truncated: bool


def _decode(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def sanitize_output(value: str | bytes | None) -> str:
    """Remove terminal control sequences and collapse progress-only frames."""
    text = _decode(value)
    text = _ANSI_ESCAPE.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    kept_lines: list[str] = []
    blank_count = 0

    for line in text.splitlines():
        stripped = line.strip()
        if _PROGRESS_LINE.match(stripped):
            continue
        if not stripped:
            blank_count += 1
            if blank_count > 2:
                continue
        else:
            blank_count = 0
        kept_lines.append(line.rstrip())

    return "\n".join(kept_lines).strip()


def truncate_text(text: str, limit: int) -> LimitedText:
    """Keep the beginning and end of long text while staying below the limit."""
    if limit <= 0:
        return LimitedText("", True)
    if len(text) <= limit:
        return LimitedText(text, False)

    marker = "\n[...truncated...]\n" if limit >= 20 else "..."
    body_limit = limit - len(marker)
    head_size = max(1, int(body_limit * 0.7))
    tail_size = max(0, body_limit - head_size)
    result = text[:head_size] + marker
    if tail_size:
        result += text[-tail_size:]
    if len(result) > limit:
        result = result[:limit]
    return LimitedText(result, True)


def limit_output_pair(
    stdout: str,
    stderr: str,
    max_chars: int,
) -> tuple[str, str, bool]:
    """Limit a command result while reserving space for diagnostics."""
    max_chars = max(500, max_chars)
    stdout_budget = int(max_chars * 0.7)
    stderr_budget = max_chars - stdout_budget

    limited_stdout = truncate_text(stdout, stdout_budget)
    if not limited_stdout.truncated:
        stderr_budget = max_chars - len(limited_stdout.text)
    limited_stderr = truncate_text(stderr, max(0, stderr_budget))
    return (
        limited_stdout.text,
        limited_stderr.text,
        limited_stdout.truncated or limited_stderr.truncated,
    )
