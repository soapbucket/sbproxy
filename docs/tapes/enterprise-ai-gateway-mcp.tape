# Credential-free enterprise AI gateway: OpenAPI-backed MCP traffic.
#
# CONFIG: examples/enterprise-ai-gateway/mcp.yml
# AUX_CONFIG: examples/enterprise-ai-gateway/upstream.yml

Output "docs/assets/enterprise-ai-gateway-mcp.gif"

Require curl
Require jq

Set Shell "bash"
Set FontSize 14
Set Width 1400
Set Height 920
Set Padding 24
Set TypingSpeed 14ms
Set Theme { "name": "sbproxy", "background": "#0d0d0f", "foreground": "#e6e6e6", "cursor": "#ffb454", "selection": "#2a2a33", "black": "#1a1a1f", "red": "#ff6b6b", "green": "#a8d96a", "yellow": "#ffb454", "blue": "#7aa2f7", "magenta": "#bb9af7", "cyan": "#7dcfff", "white": "#e6e6e6", "brightBlack": "#5c5c66", "brightRed": "#ff8888", "brightGreen": "#c3f088", "brightYellow": "#ffd194", "brightBlue": "#9bb8ff", "brightMagenta": "#d4b8ff", "brightCyan": "#7dcfff", "brightWhite": "#ffffff" }

Hide
Type `export PS1='$ '; clear`
Enter
Show

Type `# The same API becomes an MCP tool from its OpenAPI contract.`
Enter
Sleep 500ms
Type `curl -s http://127.0.0.1:8080 -H 'Host: mcp.example.com' -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl-demo","version":"1.0.0"}}}' | jq '{protocolVersion: .result.protocolVersion, server: .result.serverInfo.name}'`
Enter
Sleep 1.5s

Type `curl -s -o /dev/null -w 'initialized: HTTP %{http_code}\n' http://127.0.0.1:8080 -H 'Host: mcp.example.com' -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -H 'MCP-Protocol-Version: 2025-06-18' -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'`
Enter
Sleep 1.2s

Type `curl -s http://127.0.0.1:8080 -H 'Host: mcp.example.com' -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -H 'MCP-Protocol-Version: 2025-06-18' -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | jq -r '.result.tools[].name'`
Enter
Sleep 1.5s

Type `curl -s http://127.0.0.1:8080 -H 'Host: mcp.example.com' -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -H 'MCP-Protocol-Version: 2025-06-18' -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"local.gateway_status","arguments":{}}}' | jq -r '.result.content[].text'`
Enter
Sleep 2s
