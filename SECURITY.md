# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.x.x  | Yes       |
| < 3.0   | No       |

## Reporting a Vulnerability

If you discover a security vulnerability in Arcanum Core itself (not in a target you're testing), please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email security concerns to the maintainers via GitHub private vulnerability reporting
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 1 week
- **Fix**: Within 2 weeks for critical issues

## Scope

The following are in scope for security reports:

- Command injection in the Arcanum application itself
- Sandbox escape vulnerabilities
- Authentication/authorization bypass in the Web UI
- Sensitive data exposure (credentials, tokens)
- Dependency vulnerabilities with exploitable impact

## Responsible Use

Arcanum Core is a security testing tool. Users are responsible for:

- Obtaining proper authorization before testing any target
- Following all applicable laws and regulations
- Responsible disclosure of vulnerabilities found during testing
- Never using this tool against systems without explicit permission

## Sandbox Security

The Docker sandbox is designed with defense-in-depth. Containers are launched
(see `arcanum/sandbox/docker.py`) with:

- Non-root user (`--user nobody`)
- All Linux capabilities dropped (`--cap-drop=ALL`)
- No privilege escalation (`--security-opt no-new-privileges`)
- Memory limited to 4GB with swap disabled, plus `--pids-limit` and `--cpus`
- No privileged mode
- Optional network isolation (`network=False` → `--network none`)

Because the sandbox is unprivileged, `nmap` uses a TCP connect scan (`-sT`,
auto-applied) rather than a raw-socket SYN scan. If the sandbox image is
unavailable, command execution is refused rather than run on the host.

Report any sandbox escape vectors as critical vulnerabilities.

## Web UI / API Security

- The server binds to `127.0.0.1` by default. Only expose it on `0.0.0.0`
  behind a TLS-terminating reverse proxy with its own authentication.
- Every API route and the WebSocket require a token. Set `ARCANUM_API_TOKEN`
  for a stable secret; if unset, an ephemeral per-process token is generated
  and injected into the bundled UI (printed to the log for external clients).
- CORS defaults to loopback origins; override with `ARCANUM_CORS_ORIGINS`.
- Stash values are masked in list views; request full values explicitly.
- Reports are rendered with HTML auto-escaping to prevent stored XSS from
  target-derived content.
