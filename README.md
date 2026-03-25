# mcp-toon-proxy
A transparent MCP proxy that intercepts tool call responses from any MCP server and re-encodes JSON content into the [TOON format](https://github.com/toon-format/toon-go) — a compact, token-efficient representation of structured data. This reduces the number of tokens consumed when Claude processes large JSON payloads returned by tools, without requiring any changes to the upstream MCP server.
## How it works
The proxy sits between Claude and your MCP server. It tracks outgoing `tools/call` requests and, when the server responds, converts any JSON found in `text` content blocks to TOON before forwarding the response to Claude. Non-tool-call messages are passed through unchanged.
Three transport modes are supported:
- **stdio** — wraps a local MCP server process
- **http** — connects to an HTTP (streamable) MCP server
- **sse** — connects to a legacy SSE-based MCP server
## Build
```sh
cd mcp-toon-proxy
go build -o mcp-toon-proxy .
```
Optionally, install to your Go bin directory so it is on your `$PATH`:
```sh
go install .
```
## Usage
```
mcp-toon-proxy stdio <command> [args...]
mcp-toon-proxy http  <url> [Header:Value ...]
mcp-toon-proxy sse   <url> [Header:Value ...]
```
## Claude Code — MCP settings
Configure the proxy in your Claude Code MCP settings. The global settings file is `~/.claude/claude.json`; project-level settings live in `.claude/claude.json` at the repo root.
### stdio (local process)
Replace the server's `command` with `mcp-toon-proxy` and prepend `stdio` as the first argument:
```json
{
  "mcpServers": {
    "my-server": {
      "command": "mcp-toon-proxy",
      "args": ["stdio", "node", "/path/to/my-mcp-server/index.js"]
    }
  }
}
```
### http (streamable HTTP)
```json
{
  "mcpServers": {
    "my-remote-server": {
      "command": "mcp-toon-proxy",
      "args": ["http", "https://my-mcp-server.example.com/mcp"]
    }
  }
}
```
Custom request headers can be appended as `Header:Value` arguments:
```json
"args": ["http", "https://my-mcp-server.example.com/mcp", "X-Api-Key:my-key"]
```
### sse (legacy SSE)
```json
{
  "mcpServers": {
    "my-sse-server": {
      "command": "mcp-toon-proxy",
      "args": ["sse", "https://my-mcp-server.example.com/sse"]
    }
  }
}
```
## OAuth
For `http` and `sse` modes, the proxy supports OAuth 2.0 authorization code flow with PKCE (RFC 7636). When a server returns a `401`, the proxy automatically:
1. Discovers the authorization server via RFC 8414 / RFC 9728 metadata endpoints
2. Performs dynamic client registration (RFC 7591) if available
3. Opens your browser for the authorization flow
4. Caches tokens in `~/.claude/mcp-toon-proxy-tokens/` for reuse across sessions
Token refresh is attempted automatically on subsequent `401` responses.
