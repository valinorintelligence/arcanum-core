# Arcanum Core

**Autonomous AI-Powered Security Reconnaissance Platform**

Arcanum Core is an open-source, autonomous security reconnaissance and penetration testing platform that combines a self-hosted LLM with an isolated execution environment. It delivers a CLI (TUI), a Web UI, and integrates 40+ professional pentesting tools with AI-driven automation.

## Features

- **3 Interaction Modes** — Autopilot (fully autonomous), Copilot (AI suggests, you approve), Manual (you drive, AI advises)
- **40+ Security Tools** — Recon, Web, Network, Credentials, Exploitation, Post-Exploit, OSINT
- **Self-Hosted LLM** — Ollama-based, no API keys, no cloud dependencies
- **Isolated Sandbox** — All commands run in a hardened Kali Linux Docker container
- **Dual Interface** — Rich terminal TUI + Web UI dashboard
- **Persistent Ops** — Named workspaces per engagement with session persistence
- **CVE Knowledge Base** — 250K+ CVEs with full-text search
- **Cross-Op Stash** — Share artifacts (credentials, hosts, payloads) across operations
- **Report Generation** — PDF, HTML, Markdown, JSON with CVSS scoring

## Quick Start

```bash
# Install
pip install arcanum-core

# Check requirements
arcanum doctor

# Build the sandbox
arcanum sandbox build

# Launch autonomous assessment
arcanum autopilot example.com

# Launch with AI assistance
arcanum copilot example.com

# Manual mode
arcanum manual

# Start Web UI
arcanum serve --port 8000
```

## Requirements

- Python 3.11+
- Docker (for sandbox execution)
- Ollama (for self-hosted LLM)
- Recommended: 24GB+ VRAM GPU for optimal LLM performance

## Architecture

```
arcanum-core/
├── arcanum/
│   ├── agent/        # AI agent engine, LLM client, tool orchestration
│   ├── api/          # FastAPI backend + WebSocket streaming
│   ├── cli/          # Textual TUI with 3 interaction modes
│   ├── core/         # Config, database, CVE KB, stash, reports, alerts
│   ├── sandbox/      # Docker container + browser automation
│   └── tools/        # 40-tool registry with 7 categories
├── frontend/         # Alpine.js + Tailwind Web UI
├── docker/           # Kali sandbox + app Dockerfiles
└── tests/            # Unit + integration tests
```

## CLI Commands

```bash
arcanum autopilot <target>       # Full autonomous assessment
arcanum copilot <target>         # AI-assisted with approval
arcanum manual                   # Manual mode with AI advice
arcanum ops list|new|resume|delete  # Operation management
arcanum stash list|add|pull      # Artifact sharing
arcanum cve search <query>       # CVE lookup
arcanum serve [--port 8000]      # Web UI server
arcanum doctor                   # System check
```

## Tool Arsenal (40 tools)

| Category | Tools |
|----------|-------|
| **Recon** | subfinder, dnsx, nmap, masscan, httpx, katana, theHarvester |
| **Web** | nuclei, sqlmap, dalfox, feroxbuster, ffuf, arjun, wpscan, testssl, graphqlmap, jwt_tool |
| **Network** | netexec, snmpwalk, tshark, bettercap, chisel |
| **Creds** | hashcat, hydra, haiti, trufflehog, seclists |
| **Exploit** | metasploit, pwncat, pwntools, sliver |
| **Post** | linpeas, winpeas, impacket, bloodhound, mimikatz |
| **OSINT** | sherlock, holehe, exiftool, gowitness |

## Development

```bash
# Clone and install
git clone https://github.com/foxnode/arcanum-core.git
cd arcanum-core
pip install -e ".[dev]"

# Run tests
pytest --cov=arcanum

# Lint
ruff check arcanum/
```

## License

MIT License - see [LICENSE](LICENSE)

---

*Built with Claude Code | Foxnode Security*
