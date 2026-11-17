import pytest

from kali_mcp.core.executor import CommandRunner
from kali_mcp.server import create_server


def test_added_tools_build_expected_commands(monkeypatch, tmp_path):
    (tmp_path / "targets.txt").write_text("https://example.test\n", encoding="utf-8")
    (tmp_path / "memory.raw").write_bytes(b"memory")
    (tmp_path / "rules.yar").write_text('rule demo { condition: true }', encoding="utf-8")
    (tmp_path / "sample.bin").write_bytes(b"sample")
    monkeypatch.setenv("KALI_MCP_WORKSPACE", str(tmp_path))

    commands = []

    def capture(self, argv, *, timeout):
        commands.append(argv)
        return {"success": True}

    monkeypatch.setattr(CommandRunner, "run", capture)
    server = create_server()

    def call(name, **kwargs):
        return server._tool_manager.get_tool(name).fn(**kwargs)

    call("subdomain_discover", domain="example.test", engine="amass")
    assert commands[-1] == ["amass", "enum", "-passive", "-d", "example.test"]
    call("http_probe", target="example.test")
    assert commands[-1][0] == "httpx-toolkit"
    call("nuclei_scan", target="https://example.test")
    assert commands[-1][0] == "nuclei"
    call("tls_scan", host="example.test")
    assert commands[-1] == ["sslscan", "--no-colour", "example.test:443"]
    call("smb_shares", host="example.test")
    assert commands[-1] == ["smbclient", "-L", "//example.test", "-N"]
    call("ldap_query", host="example.test", base_dn="dc=example,dc=test")
    assert commands[-1][0] == "ldapsearch"
    call("volatility_analyze", image_path="memory.raw")
    assert commands[-1][0] == "vol"
    call("yara_scan", rule_path="rules.yar", target_path="sample.bin")
    assert commands[-1][0] == "yara"


def test_added_tools_reject_unbounded_inputs(monkeypatch, tmp_path):
    monkeypatch.setenv("KALI_MCP_WORKSPACE", str(tmp_path))
    server = create_server()

    def call(name, **kwargs):
        return server._tool_manager.get_tool(name).fn(**kwargs)

    with pytest.raises(ValueError, match="exactly one"):
        call("http_probe", target="example.test", targets_file="targets.txt")
    with pytest.raises(ValueError, match="rate_limit"):
        call("nuclei_scan", target="example.test", rate_limit=1000)
    with pytest.raises(ValueError, match="port"):
        call("tcp_connect", host="example.test", port=0)
