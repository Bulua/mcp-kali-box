import ast
import base64
import json

import pytest

from kali_mcp.core.executor import CommandRunner
from kali_mcp.server import create_server


def call(server, name, **kwargs):
    return server._tool_manager.get_tool(name).fn(**kwargs)


def test_ffuf_and_bbot_commands(monkeypatch, tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin" + chr(10), encoding="utf-8")
    monkeypatch.setenv("KALI_MCP_WORKSPACE", str(tmp_path))
    commands = []

    def capture(self, argv, *, timeout):
        commands.append(argv)
        return {"success": True}

    monkeypatch.setattr(CommandRunner, "run", capture)
    server = create_server()
    call(server, "ffuf_scan", url="https://example.test", dictionary_path=str(wordlist))
    assert commands[-1][0] == "ffuf"
    assert "-rate" in commands[-1]
    result = call(server, "bbot_scan", target="example.test", modules=["dnsdumpster"])
    assert commands[-1][0:3] == ["bbot", "-s", "example.test"]
    assert result["output_directory"].startswith(str(tmp_path))
    with pytest.raises(ValueError):
        call(server, "bbot_scan", target="-x", modules=["dnsdumpster"])


def test_api_diff_omits_session_secrets(monkeypatch):
    calls = []

    def capture(self, argv, *, timeout):
        calls.append(argv)
        body = '{"owner":"a"}' if len(calls) == 1 else '{"owner":"b"}'
        return {"success": True, "stdout": body + chr(10) + "__STATUS__:200"}

    monkeypatch.setattr(CommandRunner, "run", capture)
    result = call(create_server(), "api_response_diff", url="https://example.test/api",
                  headers_a={"Authorization": "Bearer secret-a"}, headers_b={"Authorization": "Bearer secret-b"})
    assert result["status_a"] == "200"
    assert result["changes"] == [{"path": "/owner", "change": "value_changed"}]
    assert "secret" not in json.dumps(result)


def test_jwt_browser_and_binary_helpers(monkeypatch, tmp_path):
    monkeypatch.setenv("KALI_MCP_WORKSPACE", str(tmp_path))
    server = create_server()
    def encode(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    token = encode({"alg": "none"}) + "." + encode({"exp": 1}) + "."
    result = call(server, "jwt_inspect", token=token)
    assert result["signature_verified"] is False
    assert "token is expired" in result["warnings"]

    commands = []
    def capture(self, argv, *, timeout):
        commands.append(argv)
        return {"success": True}
    monkeypatch.setattr(CommandRunner, "run", capture)
    call(server, "browser_api_capture", url="https://example.test")
    ast.parse(commands[-1][2])

    (tmp_path / "old.bin").write_bytes(b"abcd")
    (tmp_path / "new.bin").write_bytes(b"abXd")
    diff = call(server, "binary_byte_diff", old_path="old.bin", new_path="new.bin")
    assert diff["changed_ranges"] == [{"start": 2, "end": 3}]
    assert diff["same"] is False
