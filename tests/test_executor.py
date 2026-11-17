import sys

from kali_mcp.core.executor import CommandRunner


def test_command_runner_runs_without_shell(tmp_path):
    runner = CommandRunner(workspace=tmp_path, max_output_chars=8000)
    result = runner.run([sys.executable, "-c", "print('kali-mcp-ok')"], timeout=10)
    assert result["success"] is True
    assert "kali-mcp-ok" in result["stdout"]
    assert result["returncode"] == 0


def test_command_runner_reports_timeout(tmp_path, monkeypatch):
    runner = CommandRunner(workspace=tmp_path, max_output_chars=8000)
    result = runner.run([sys.executable, "-c", "import time; time.sleep(3)"], timeout=1)
    assert result["success"] is False
    assert result["timed_out"] is True
    assert result["error"]["type"] == "TimeoutError"
    assert result["full_output_path"] is not None
