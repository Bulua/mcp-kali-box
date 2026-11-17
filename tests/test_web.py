import pytest

from kali_mcp.server import create_server
from kali_mcp.core import paths


def test_directory_scan_uses_engine_specific_url(monkeypatch, tmp_path):
    dictionary = tmp_path / "common.txt"
    dictionary.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr(paths, "resolve_tool_input_file", lambda path: dictionary)

    commands = []

    def capture_command(self, argv, *, timeout):
        commands.append(argv)
        return {"success": True}

    monkeypatch.setattr("kali_mcp.core.executor.CommandRunner.run", capture_command)
    scan = create_server()._tool_manager.get_tool("directory_scan").fn

    scan("http://127.0.0.1:8000/app/", engine="gobuster")
    assert commands[-1][:4] == ["gobuster", "dir", "-u", "http://127.0.0.1:8000/app/"]

    scan("http://127.0.0.1:8000/app/", engine="ffuf")
    assert commands[-1][commands[-1].index("-u") + 1] == "http://127.0.0.1:8000/app/FUZZ"

    scan("http://127.0.0.1:8000/app/FUZZ.php", engine="ffuf")
    assert commands[-1][commands[-1].index("-u") + 1] == "http://127.0.0.1:8000/app/FUZZ.php"

    with pytest.raises(ValueError, match="Gobuster requires a base URL"):
        scan("http://127.0.0.1:8000/app/FUZZ", engine="gobuster")
