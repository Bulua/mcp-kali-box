from kali_mcp.core.executor import CommandRunner
from kali_mcp.server import create_server


def test_nmap_tcp_connect_avoids_raw_sockets(monkeypatch):
    commands = []

    def capture(self, argv, *, timeout):
        commands.append((argv, timeout))
        return {"success": True}

    monkeypatch.setattr(CommandRunner, "run", capture)
    scan = create_server()._tool_manager.get_tool("nmap_scan").fn

    scan(target="192.0.2.10", scan_type="tcp_connect", top_ports=1000, timeout=180)
    argv, timeout = commands[-1]
    assert argv == [
        "nmap", "-T3", "--max-rate=1000", "--open", "--unprivileged",
        "-Pn", "--disable-arp-ping", "-sT", "-sV", "--top-ports", "1000",
        "192.0.2.10",
    ]
    assert timeout == 180

    scan(target="192.0.2.10", scan_type="syn")
    assert "--unprivileged" not in commands[-1][0]
    assert "-sS" in commands[-1][0]

    scan(target="192.0.2.10", scan_type="tcp_connect", os_detection=True)
    assert "--unprivileged" not in commands[-1][0]
    assert "-O" in commands[-1][0]
