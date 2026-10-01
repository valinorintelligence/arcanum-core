FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive

# Install base system tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    curl wget git jq unzip \
    # Recon tools
    subfinder dnsx nmap masscan httpx-toolkit katana theharvester \
    # Web tools
    nuclei sqlmap feroxbuster ffuf arjun wpscan \
    # Network tools
    crackmapexec snmp tshark chisel \
    # Creds tools
    hashcat hydra \
    # Exploit tools
    metasploit-framework \
    # Post-exploit
    impacket-scripts \
    # OSINT
    exiftool gowitness \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install precompiled Kali packages and build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential python3-dev cmake pkg-config libssl-dev \
        python3-pwntools python3-netifaces python3-requests \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --break-system-packages --no-cache-dir --no-deps pwncat-cs \
    && pip3 install --break-system-packages --no-cache-dir \
        sherlock-project holehe trufflehog

# Install jwt_tool from GitHub (not available on PyPI)
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool && \
    ln -s /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool && \
    chmod +x /opt/jwt_tool/jwt_tool.py && \
    pip3 install --break-system-packages --no-cache-dir pycryptodomex termcolor requests

# Install SecLists wordlists
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/seclists

# Create workspace
RUN mkdir -p /workspace && chown nobody:nogroup /workspace
WORKDIR /workspace

# Fix nmap execution under no-new-privileges
RUN setcap -r /usr/lib/nmap/nmap 2>/dev/null || true

ENV HOME=/workspace
USER nobody
CMD ["/bin/bash"]
