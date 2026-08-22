# Home Assistant Diagnostic MCP

Read-only Home Assistant OS app exposing a remote MCP Streamable HTTP endpoint at `/mcp`. It complements, rather than replaces, Home Assistant's native MCP endpoint.

## Install

1. Put this repository in a Git repository reachable by Home Assistant, then open **Settings > Apps > App store > three-dot menu > Repositories**.
2. Add that Git repository URL, refresh the store, and install **Home Assistant Diagnostic MCP**.
3. Generate a token with `openssl rand -base64 48` and set it as `mcp_auth_token` in the app configuration. The app will refuse to start with a token shorter than 32 characters.
4. Start the app. Its host port is `8765`; expose it only through a TLS reverse proxy if external access is required.

Health check:

```sh
curl http://HOME_ASSISTANT_LAN_IP:8765/healthz
```

The expected response is `{"status":"ok"}`. MCP requests require `Authorization: Bearer <token>`.

## Reverse Proxy

Proxy `https://ha-diagnostics.example.com/mcp` to `http://HOME_ASSISTANT_LAN_IP:8765/mcp`, preserving `Authorization`, `Content-Type`, `Accept`, and streaming responses. Terminate TLS at the proxy. Do not expose the plain LAN port to the Internet. Ingress is intentionally not used because it is browser-session oriented rather than a general remote MCP transport.

## MCP Clients

Generic Streamable HTTP configuration uses URL `https://ha-diagnostics.example.com/mcp` with header `Authorization: Bearer <token>`.

OpenCode example:

```json
{
  "mcp": {
    "home-assistant-diagnostics": {
      "type": "remote",
      "url": "https://ha-diagnostics.example.com/mcp",
      "headers": { "Authorization": "Bearer YOUR_LONG_RANDOM_TOKEN" }
    }
  }
}
```

Claude Code example (use an environment variable rather than placing the token in shell history):

```sh
export HA_DIAGNOSTICS_MCP_TOKEN="$(openssl rand -base64 48)"
claude mcp add --transport http \
  --header "Authorization: Bearer $HA_DIAGNOSTICS_MCP_TOKEN" \
  home-assistant-diagnostics https://ha-diagnostics.example.com/mcp
```

Codex `config.toml` example:

```toml
[mcp_servers.home_assistant_diagnostics]
url = "https://ha-diagnostics.example.com/mcp"
bearer_token_env_var = "HA_DIAGNOSTICS_MCP_TOKEN"
```

Use a second MCP connection for Home Assistant's native MCP: `https://homeassistant.example.com/api/mcp`. Native MCP is for Assist context and allowed entity operations; this app is configuration, history, registry, trace, and error-log evidence only.

For MCP Inspector, run `npx @modelcontextprotocol/inspector`, select Streamable HTTP, enter the diagnostic URL, and add the bearer header.

## Security Model

- `/homeassistant` is the only exceptional mount and is declared read-only.
- No host network, host PID/DBus, Docker API, Supervisor API, device, privilege, or shell access is requested.
- The REST provider contains GET requests only. The WebSocket provider hardcodes a small read-only command allowlist.
- Configuration access is limited to root YAML files and `packages/**/*.yaml`; `secrets.yaml`, sensitive `.storage` files, paths outside the mount, and non-YAML files are rejected.
- Structured output is recursively redacted and response limits are disclosed to clients.
- `trace/list` and `trace/get` are Core WebSocket commands used by the frontend but are not listed in the public WebSocket documentation. They are isolated and may require an administrator-scoped Supervisor proxy token on a particular Core release.

This version intentionally provides no services, writes, reloads, restarts, configuration validation POST, arbitrary HTTP/WebSocket calls, SQL, or filesystem tools.
