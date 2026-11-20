"""Focused helpers for the ARTEX security skills."""

from __future__ import annotations

import base64
import hashlib
import time
import json
import re
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from ..core.executor import CommandRunner
from ..core.paths import resolve_workspace_path, safe_child, workspace_root


def _target(value: str) -> str:
    if not value or not value.strip() or value.strip().startswith("-"):
        raise ValueError("target must be a non-empty value")
    return value.strip()


def _changes(left: Any, right: Any, limit: int = 100) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []

    def walk(a: Any, b: Any, path: str) -> None:
        if len(out) >= limit:
            return
        if isinstance(a, dict) and isinstance(b, dict):
            for key in sorted(a.keys() | b.keys()):
                if key not in a or key not in b:
                    out.append({"path": path + "/" + key, "change": "added" if key not in a else "removed"})
                else:
                    walk(a[key], b[key], path + "/" + key)
        elif isinstance(a, list) and isinstance(b, list):
            if len(a) != len(b):
                out.append({"path": path, "change": "array_length"})
            for i, (x, y) in enumerate(zip(a, b)):
                walk(x, y, path + "/" + str(i))
        elif a != b:
            out.append({"path": path or "/", "change": "value_changed"})

    walk(left, right, "")
    return out


def _decode(segment: str) -> dict[str, Any]:
    value = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    if not isinstance(value, dict):
        raise ValueError("JWT header and payload must be objects")
    return value


def register_skill_additions(mcp: MCPServer, runner: CommandRunner) -> None:
    @mcp.tool(name="bbot_scan")
    def bbot_scan(
        target: str,
        modules: list[str],
        mode: Literal["passive", "active"] = "passive",
        scan_name: str = "recon",
        timeout: int = 300,
    ) -> dict[str, Any]:
        """Run selected bbot modules; active scanning needs explicit mode."""
        target = _target(target)
        if not modules or len(modules) > 20 or any(not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", m) for m in modules):
            raise ValueError("modules must contain 1-20 valid module names")
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", scan_name):
            raise ValueError("invalid scan_name")
        output = safe_child(workspace_root(), "bbot/" + scan_name)
        argv = ["bbot", "-t" if mode == "active" else "-s", target,
                "-m", *modules, "-om", "json,txt", "-o", str(output),
                "-n", scan_name, "-y", "--no-deps", "--no-color"]
        result = runner.run(argv, timeout=timeout)
        result["output_directory"] = str(output)
        return result

    @mcp.tool(name="api_response_diff")
    def api_response_diff(
        url: str,
        headers_a: dict[str, str],
        headers_b: dict[str, str],
        method: str = "GET",
        data: str | None = None,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Replay a request with two test sessions and compare response structure."""
        url = _target(url)
        if not url.startswith(("http://", "https://")) or not re.fullmatch(r"[A-Za-z]+", method):
            raise ValueError("url must be HTTP(S) and method must be alphabetic")

        def request(headers: dict[str, str]) -> dict[str, Any]:
            argv = ["curl", "--silent", "--show-error", "--max-time", str(max(1, timeout - 1)),
                    "-X", method.upper(), "-w", "\n__STATUS__:%{http_code}"]
            for key, value in headers.items():
                if not re.fullmatch(r"[A-Za-z0-9-]+", key) or chr(10) in value or chr(13) in value:
                    raise ValueError("invalid header")
                argv.extend(["-H", key + ": " + value])
            if data is not None:
                argv.extend(["--data-binary", data])
            return runner.run([*argv, url], timeout=timeout)

        left, right = request(headers_a), request(headers_b)
        if not left.get("success") or not right.get("success"):
            return {"success": False, "left": left, "right": right}
        if left.get("truncated") or right.get("truncated"):
            return {"success": False, "error": {"type": "TruncatedResponse", "message": "response exceeded the output cap; narrow the request before comparing"}}

        def split(result: dict[str, Any]) -> tuple[str, str]:
            body, marker, status = result.get("stdout", "").rpartition("\n__STATUS__:")
            return (body, status.strip()) if marker else (result.get("stdout", ""), "unknown")

        body_a, status_a = split(left)
        body_b, status_b = split(right)
        try:
            parsed_a, parsed_b = json.loads(body_a), json.loads(body_b)
        except json.JSONDecodeError:
            parsed_a, parsed_b = body_a, body_b
        return {"success": True, "status_a": status_a, "status_b": status_b,
                "same_body": body_a == body_b, "changes": _changes(parsed_a, parsed_b),
                "note": "A difference is evidence to review, not proof of an authorization flaw."}

    @mcp.tool(name="jwt_inspect")
    def jwt_inspect(token: str) -> dict[str, Any]:
        """Decode JWT metadata offline; does not verify or brute-force signatures."""
        parts = token.strip().split(".")
        if len(parts) != 3 or len(token) > 16384:
            raise ValueError("JWT must have three bounded segments")
        header, payload = _decode(parts[0]), _decode(parts[1])
        now = int(time.time())
        warnings = ["unsigned algorithm declared"] if str(header.get("alg", "")).lower() == "none" else []
        if isinstance(payload.get("exp"), (int, float)) and payload["exp"] <= now:
            warnings.append("token is expired")
        if isinstance(payload.get("nbf"), (int, float)) and payload["nbf"] > now:
            warnings.append("token is not yet valid")
        return {"header": header, "claims": payload, "algorithm": header.get("alg"),
                "has_signature": bool(parts[2]), "signature_verified": False,
                "warnings": warnings}

    @mcp.tool(name="browser_api_capture")
    def browser_api_capture(url: str, output_name: str = "capture", timeout: int = 60) -> dict[str, Any]:
        """Capture page URL, title and requests with headless Chromium."""
        if not url.startswith(("http://", "https://")):
            raise ValueError("url must be HTTP(S)")
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", output_name):
            raise ValueError("invalid output_name")
        output = safe_child(workspace_root(), "browser/" + output_name + ".json")
        output.parent.mkdir(parents=True, exist_ok=True)
        script = """import json, sys
from playwright.sync_api import sync_playwright

url, out = sys.argv[1:]
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=['--no-sandbox'])
    page = browser.new_page()
    requests = []
    page.on('request', lambda request: requests.append({'method': request.method, 'url': request.url}))
    page.goto(url, wait_until='domcontentloaded', timeout=30000)
    with open(out, 'w', encoding='utf-8') as handle:
        json.dump({'url': page.url, 'title': page.title(), 'requests': requests[:1000]}, handle)
    browser.close()
"""
        result = runner.run(["python3", "-c", script, url, str(output)], timeout=timeout)
        result["output_path"] = str(output)
        return result

    @mcp.tool(name="binary_byte_diff")
    def binary_byte_diff(old_path: str, new_path: str) -> dict[str, Any]:
        """Compare two local binaries by size, hash and changed byte ranges; no function analysis."""
        old = resolve_workspace_path(old_path, must_exist=True, kind="file")
        new = resolve_workspace_path(new_path, must_exist=True, kind="file")
        a, b = old.read_bytes(), new.read_bytes()
        ranges: list[dict[str, int]] = []
        begin: int | None = None
        for i in range(max(len(a), len(b))):
            changed = i >= len(a) or i >= len(b) or a[i] != b[i]
            if changed and begin is None:
                begin = i
            elif not changed and begin is not None:
                ranges.append({"start": begin, "end": i})
                begin = None
            if len(ranges) >= 1000:
                break
        if begin is not None:
            ranges.append({"start": begin, "end": max(len(a), len(b))})
        return {"same": a == b, "old_size": len(a), "new_size": len(b),
                "old_sha256": hashlib.sha256(a).hexdigest(), "new_sha256": hashlib.sha256(b).hexdigest(),
                "changed_ranges": ranges[:1000], "truncated": len(ranges) > 1000,
                "note": "Byte changes do not establish a vulnerability or source-level root cause."}

    @mcp.tool(name="binary_diff")
    def binary_diff(old_path: str, new_path: str, output_name: str = "binary-diff", timeout: int = 600) -> dict[str, Any]:
        """Diff two local builds with ghidriff, when its Ghidra toolchain is installed."""
        old = resolve_workspace_path(old_path, must_exist=True, kind="file")
        new = resolve_workspace_path(new_path, must_exist=True, kind="file")
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", output_name):
            raise ValueError("invalid output_name")
        output = safe_child(workspace_root(), "binary-diff/" + output_name)
        output.mkdir(parents=True, exist_ok=True)
        result = runner.run(["ghidriff", str(old), str(new), "-o", str(output)], timeout=timeout)
        result["output_directory"] = str(output)
        return result
