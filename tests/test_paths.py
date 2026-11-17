import pytest

from kali_mcp.core.paths import resolve_workspace_path


def test_resolve_workspace_path_rejects_traversal(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_WORKSPACE", str(tmp_path))
    with pytest.raises(ValueError, match="escapes"):
        resolve_workspace_path("../outside.txt")


def test_resolve_workspace_path_rejects_absolute_path(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_WORKSPACE", str(tmp_path))
    with pytest.raises(ValueError, match="absolute"):
        resolve_workspace_path(str(tmp_path / "file.txt"))
