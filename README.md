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
│  │  ├── discovery.py       # subdomains, HTTP probing, templates, TLS
│  │  ├── internal.py        # SMB, RPC, LDAP, netcat, socat
│  │  ├── forensics.py       # Volatility 3 and YARA
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
copy .env.example .env
notepad .env
docker compose build
docker compose up -d
curl http://127.0.0.1:8000/health
```

The image uses `kalilinux/kali-rolling:latest`. The container listens on all
interfaces inside Docker at port 8000, but Compose publishes only
`127.0.0.1:8000` to the host by default. Set `KALI_MCP_BIND_IP=0.0.0.0` in
`.env` to publish the service on every host interface, or set it to a specific
host interface IP to expose it only on that network. Set
`KALI_MCP_HOST_PORT` to change the host-side port without changing the
container's internal port. The local `workspace/` directory is mounted at
`/workspace`; oversized reports are written to `/workspace/reports`.

The build uses the Tsinghua TUNA Kali mirror for APT. The minimal Kali
image does not necessarily contain the CA bundle needed for HTTPS before
`ca-certificates` is installed, while apt still verifies repository signatures
through Kali's GPG key. Python packages use the Tencent Cloud PyPI mirror by default.
The base image still comes from Docker Hub; set `KALI_BASE_IMAGE` to a trusted
registry mirror when Docker Hub is slow in your environment. To switch mirrors,
change `KALI_APT_MIRROR`, `PYPI_INDEX_URL`, or `KALI_BASE_IMAGE` in
`docker-compose.yml`, or build directly with another apt mirror:

```powershell
docker build --build-arg KALI_APT_MIRROR=http://mirrors.tuna.tsinghua.edu.cn/kali -f docker/Dockerfile -t kali-mcp-server:0.1.0 .
```

Set `KALI_MCP_TRANSPORT` to `dual`, `sse`, or `streamable-http` if you want a
single transport. The default is `dual`.

## Authentication and Remote Access

All MCP endpoints require a bearer token. The token is read only from
`KALI_MCP_API_TOKEN`, must contain exactly 64 hexadecimal characters, and is
never baked into the image. Generate one with:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

Create `.env` from `.env.example`, set the generated token, and choose the host
binding:

```env
# Bind only to the local host:
KALI_MCP_BIND_IP=127.0.0.1

# Or publish on every interface after enabling the required firewall rule:
KALI_MCP_BIND_IP=0.0.0.0

# Optional: use a non-default host-side port:
KALI_MCP_HOST_PORT=27180

KALI_MCP_API_TOKEN=<64-hex-character-token>
```

Remote callers must send:

```http
Authorization: Bearer <64-hex-character-token>
```

`/health` remains unauthenticated so Docker can run its health check, but it
exposes only service status. `/mcp`, `/sse`, and `/messages` return HTTP 401
without a valid token.

For a trusted LAN or VPN, `http://<server-ip>:<host-port>/mcp` plus the bearer
header is the minimum viable setup. For an internet-facing deployment, terminate TLS
first with a reverse proxy and restrict source IP addresses where possible. A
bearer token sent over plain HTTP can be intercepted, so do not expose plain
HTTP directly to the public internet.

## Additional tools

The server also includes Subfinder and passive Amass subdomain discovery,
HTTPX probes, Nuclei, Feroxbuster, sslscan, testssl.sh, SMB and RPC
enumeration, netcat and socat connectivity checks, LDAP search, Volatility 3
memory analysis, and YARA file matching. File inputs must be in the mounted
`workspace/` directory. Nuclei template availability depends on the image's
template package or a separately provisioned template set; update templates
before relying on its scan coverage.

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
      "url": "http://127.0.0.1:8000/mcp",
      "headers": {
        "Authorization": "Bearer <64-hex-character-token>"
      }
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
      "url": "http://127.0.0.1:8000/sse",
      "headers": {
        "Authorization": "Bearer <64-hex-character-token>"
      }
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
      "headers": {
        "Authorization": "Bearer <64-hex-character-token>"
      },
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
- The container runs as root with Docker privileged mode so raw-packet scans,
  debuggers, and other Kali tools can use container privileges. A privileged
  container has broad access to host devices and kernel interfaces; grant MCP
  access only to trusted users and protect remote connections with TLS.
- `nmap_scan` defaults to TCP connect scanning with Nmap's unprivileged mode
  and skips host discovery/ARP probing. SYN, UDP, and OS detection modes use
  raw sockets.

The bind-mounted `workspace/` is writable by container root. On Linux,
files created there may be owned by root on the host.

## Local Development Checks

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements-dev.txt
.\.venv\Scripts\pytest
.\.venv\Scripts\python -m compileall src
.\.venv\Scripts\ruff check src tests
```
