ARG KALI_BASE_IMAGE=kalilinux/kali-rolling:latest
FROM ${KALI_BASE_IMAGE}

ARG DEBIAN_FRONTEND=noninteractive
ARG KALI_APT_MIRROR=http://mirrors.tuna.tsinghua.edu.cn/kali
ARG PYPI_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/

RUN printf 'deb %s kali-rolling main contrib non-free non-free-firmware\n' "$KALI_APT_MIRROR" > /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/kali.sources

RUN apt-get update && apt-get install -y --no-install-recommends \
      amass \
      binutils \
      binwalk \
      ca-certificates \
      curl \
      dirb \
      dnsutils \
      enum4linux-ng \
      ffuf \
      feroxbuster \
      file \
      gdb \
      gobuster \
      hashcat \
      hydra \
      httpx-toolkit \
      impacket-scripts \
      john \
      ldap-utils \
      libimage-exiftool-perl \
      nikto \
      netcat-openbsd \
      nmap \
      nuclei \
      openvpn \
      pocl-opencl-icd \
      python3 \
      python3-pip \
      python3-venv \
      smbclient \
      socat \
      sqlmap \
      sslscan \
      subfinder \
      testssl.sh \
      tshark \
      whatweb \
      whois \
      yara \
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
    && /opt/kali-mcp/.venv/bin/pip install \
         --index-url "${PYPI_INDEX_URL}" \
         --no-cache-dir \
         --retries 10 \
         --timeout 120 \
         --upgrade pip \
    && /opt/kali-mcp/.venv/bin/pip install \
         --index-url "${PYPI_INDEX_URL}" \
         --no-cache-dir \
         --retries 10 \
         --timeout 120 \
         -r /tmp/requirements.txt \
    && /opt/kali-mcp/.venv/bin/pip install \
         --index-url "${PYPI_INDEX_URL}" \
         --no-cache-dir \
         --retries 10 \
         --timeout 120 \
         volatility3

COPY pyproject.toml README.md ./
COPY src ./src
RUN /opt/kali-mcp/.venv/bin/pip install \
      --index-url "${PYPI_INDEX_URL}" \
      --no-cache-dir \
      --no-deps \
      . \
    && command -v subfinder && command -v amass && command -v httpx-toolkit \
    && command -v nuclei && command -v smbclient && command -v enum4linux-ng \
    && command -v feroxbuster && command -v sslscan && command -v nc \
    && command -v socat && command -v ldapsearch && command -v vol \
    && command -v yara && command -v testssl && command -v impacket-rpcdump \
    && chown -R kalimcp:kalimcp /opt/kali-mcp

USER kalimcp
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/health >/dev/null || exit 1

CMD ["python", "-m", "kali_mcp"]
