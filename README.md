# Kali MCP Server

This project packages common Kali Linux tools as a containerized Model Context
Protocol (MCP) service. It uses the official Python SDK `mcp==2.3.0`, exposes
both current streamable HTTP (`/mcp`) and legacy SSE (`/sse`) on one port, and
binds that port only to the host loopback address.

Only use this server against systems and datasets you are explicitly authorized
to test. Loopback binding prevents remote clients from reaching the MCP service,
but it does not make unauthorized scanning or exploitation lawful or safe.

## Project Structure

```text
mcp-kali-box/
├── docker/
│  └── Dockerfile
├── src/kali_mcp/
│  ├── core/
│  │  ├── executor.py        # subprocess.run, timeout, sanitization, truncation
│  │  ├── output.py          # ANSI/progress cleanup and head/tail truncation
│  │  └── paths.py           # /workspace confinement
│  ├── tools/
│  │  ├── binary.py          # file, strings, binwalk, exiftool, objdump, gdb, tshark
│  │  ├── credentials.py     # hydra, john, hashcat identify/crack
│  │  ├── recon.py           # nmap, whatweb, whois, dig
│  │  ├── web.py             # gobuster/ffuf, sqlmap, nikto, curl
│  │  └── workspace.py       # file manager and Python script runner
│  ├── server.py             # MCP application factory and transports
│  └── __main__.py
├── tests/
├── docker-compose.yml
├── pyproject.toml
└── requirements.txt
```

## Build and Start

```powershell
docker compose build
docker compose up -d
curl http://127.0.0.1:8000/health
```

The image uses `kalilinux/kali-rolling:latest`. The container listens on all
interfaces inside Docker at port 8000, but Compose publishes only
`127.0.0.1:8000` to the host. The local `workspace/` directory is mounted at
`/workspace`; oversized reports are written to `/workspace/reports`.

The build first uses the Tsinghua TUNA Kali mirror over HTTP. The minimal Kali
image does not necessarily contain the CA bundle needed for HTTPS before
`ca-certificates` is installed, while apt still verifies repository signatures
through Kali's GPG key. To switch mirrors, change `KALI_APT_MIRROR` in
`docker-compose.yml`, or build directly with another mirror:

```powershell
docker build --build-arg KALI_APT_MIRROR=http://mirrors.aliyun.com/kali -f docker/Dockerfile -t kali-mcp-server:0.1.0 .
```

Set `KALI_MCP_TRANSPORT` to `dual`, `sse`, or `streamable-http` if you want a
single transport. The default is `dual`.

## Endpoints

| Purpose | URL |
|---|---|
| Health check | `http://127.0.0.1:8000/health` |
| Current MCP streamable HTTP | `http://127.0.0.1:8000/mcp` |
| Legacy MCP SSE | `http://127.0.0.1:8000/sse` |

## Claude Desktop Configuration

Newer Claude clients can use streamable HTTP:

```json
{
  "mcpServers": {
    "kali-mcp": {
      "type": "http",
      "url": "http://127.0.0.1:8000/mcp"
    }
  }
}
```

For an SSE-only client:

```json
{
  "mcpServers": {
    "kali-mcp": {
      "type": "sse",
      "url": "http://127.0.0.1:8000/sse"
    }
  }
}
```

## Cursor Configuration

Place this in the Cursor MCP configuration and restart Cursor:

```json
{
  "mcpServers": {
    "kali-mcp": {
      "url": "http://127.0.0.1:8000/mcp",
      "enabled": true
    }
  }
}
```

If your Cursor build does not accept direct HTTP MCP servers, use its remote
URL setting with `http://127.0.0.1:8000/mcp`, or select the legacy endpoint
`http://127.0.0.1:8000/sse` where SSE is supported.

## Runtime Controls

- Commands use argument arrays; no command is interpreted by a shell.
- The default subprocess timeout is 120 seconds; each tool can override it up
  to 1800 seconds.
- ANSI colors and progress-only frames are removed.
- Returned stdout and stderr are limited to 8000 characters by default.
- Oversized or timed-out output is saved under `/workspace/reports`.
- Workspace reads/writes cannot traverse outside `/workspace`.
- Hashcat uses CPU OpenCL. No GPU device is passed through by default.
- `NET_ADMIN`, `NET_RAW`, and `/dev/net/tun` support Nmap raw packets and later
  OpenVPN use while keeping the MCP endpoint local.

For a Linux host, ensure the bind-mounted workspace is writable by UID 10000:

```bash
sudo chown -R 10000:10000 ./workspace
```

Windows Docker Desktop normally handles the bind-mount permissions without a
manual ownership change.

## Local Development Checks

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements-dev.txt
.\.venv\Scripts\pytest
.\.venv\Scripts\python -m compileall src
.\.venv\Scripts\ruff check src tests
```
