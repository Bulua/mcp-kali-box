FROM kalilinux/kali-rolling:latest

ARG DEBIAN_FRONTEND=noninteractive
ARG KALI_APT_MIRROR=http://mirrors.tuna.tsinghua.edu.cn/kali

RUN printf 'deb %s kali-rolling main contrib non-free non-free-firmware\n' "$KALI_APT_MIRROR" > /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/kali.sources

RUN apt-get update && apt-get install -y --no-install-recommends \
      binutils \
      binwalk \
      ca-certificates \
      curl \
      dirb \
      dnsutils \
      ffuf \
      file \
      gdb \
      gobuster \
      hashcat \
      hydra \
      john \
      libimage-exiftool-perl \
      nikto \
      nmap \
      openvpn \
      pocl-opencl-icd \
      python3 \
      python3-pip \
      python3-venv \
      sqlmap \
      tshark \
      whatweb \
      whois \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10000 kalimcp \
    && useradd --uid 10000 --gid kalimcp --create-home --shell /usr/sbin/nologin kalimcp \
    && mkdir -p /opt/kali-mcp /workspace \
    && chown -R kalimcp:kalimcp /opt/kali-mcp /workspace

WORKDIR /opt/kali-mcp
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KALI_MCP_HOST=0.0.0.0 \
    KALI_MCP_PORT=8000 \
    KALI_MCP_TRANSPORT=dual \
    KALI_MCP_WORKSPACE=/workspace \
    PATH="/opt/kali-mcp/.venv/bin:${PATH}"

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/kali-mcp/.venv \
    && /opt/kali-mcp/.venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/kali-mcp/.venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

COPY pyproject.toml README.md ./
COPY src ./src
RUN /opt/kali-mcp/.venv/bin/pip install --no-cache-dir --no-deps . \
    && chown -R kalimcp:kalimcp /opt/kali-mcp

USER kalimcp
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/health >/dev/null || exit 1

CMD ["python", "-m", "kali_mcp"]
