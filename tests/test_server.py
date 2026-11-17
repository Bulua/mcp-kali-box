import pytest

from kali_mcp.server import create_dual_transport_app, create_server


@pytest.mark.asyncio
async def test_server_registers_all_tool_groups_and_routes():
    server = create_server()
    tools = await server.list_tools()
    tool_names = {tool.name for tool in tools}

    expected_tools = {
        "nmap_scan",
        "whatweb_scan",
        "whois_lookup",
        "dns_lookup",
        "directory_scan",
        "sqlmap_scan",
        "nikto_scan",
        "http_request",
        "hydra_brute_force",
        "john_crack_hash",
        "hashcat_identify",
        "hashcat_crack_hash",
        "file_inspect",
        "strings_extract",
        "binwalk_scan",
        "exiftool_metadata",
        "objdump_analyze",
        "gdb_batch_debug",
        "tshark_analyze_pcap",
        "workspace_file_manager",
        "run_python_script",
        "subdomain_discover",
        "http_probe",
        "nuclei_scan",
        "feroxbuster_scan",
        "tls_scan",
        "testssl_scan",
        "smb_shares",
        "enum4linux_scan",
        "tcp_connect",
        "socat_connect",
        "ldap_query",
        "impacket_rpcdump",
        "volatility_analyze",
        "yara_scan",
    }

    assert tool_names == expected_tools

    app = create_dual_transport_app()
    assert {route.path for route in app.router.routes} == {
        "/health",
        "/sse",
        "/messages",
        "/mcp",
    }
