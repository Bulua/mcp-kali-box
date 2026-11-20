import pytest

from kali_mcp.server import create_dual_transport_app, create_server


@pytest.mark.asyncio
async def test_server_registers_all_tool_groups_and_routes(monkeypatch):
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
        "ffuf_scan",
        "bbot_scan",
        "api_response_diff",
        "jwt_inspect",
        "browser_api_capture",
        "binary_byte_diff",
        "binary_diff",
    }

    assert tool_names == expected_tools

    monkeypatch.setenv("KALI_MCP_API_TOKEN", "a" * 64)
    app = create_dual_transport_app()
    assert {route.path for route in app.router.routes} == {
        "/health",
        "/sse",
        "/messages",
        "/mcp",
    }


async def test_bearer_token_middleware_rejects_invalid_token():
    from kali_mcp.server import BearerTokenMiddleware

    async def downstream(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = BearerTokenMiddleware(downstream, "a" * 64)
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "path": "/mcp",
        "headers": [(b"authorization", b"Bearer " + b"b" * 64)],
        "query_string": b"",
    }
    await middleware(scope, receive, send)

    assert messages[0]["status"] == 401


async def test_bearer_token_middleware_allows_health_without_token():
    from kali_mcp.server import BearerTokenMiddleware

    async def downstream(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = BearerTokenMiddleware(downstream, "a" * 64)
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "path": "/health",
        "headers": [],
        "query_string": b"",
    }
    await middleware(scope, receive, send)

    assert messages[0]["status"] == 200
