# Credential-free enterprise AI gateway: conventional API traffic.
#
# CONFIG: examples/enterprise-ai-gateway/api.yml
# AUX_CONFIG: examples/enterprise-ai-gateway/upstream.yml

Output "docs/assets/enterprise-ai-gateway-api.gif"

Require curl
Require jq

Set Shell "bash"
Set FontSize 16
Set Width 1280
Set Height 460
Set Padding 24
Set TypingSpeed 25ms
Set Theme { "name": "sbproxy", "background": "#0d0d0f", "foreground": "#e6e6e6", "cursor": "#ffb454", "selection": "#2a2a33", "black": "#1a1a1f", "red": "#ff6b6b", "green": "#a8d96a", "yellow": "#ffb454", "blue": "#7aa2f7", "magenta": "#bb9af7", "cyan": "#7dcfff", "white": "#e6e6e6", "brightBlack": "#5c5c66", "brightRed": "#ff8888", "brightGreen": "#c3f088", "brightYellow": "#ffd194", "brightBlue": "#9bb8ff", "brightMagenta": "#d4b8ff", "brightCyan": "#7dcfff", "brightWhite": "#ffffff" }

Hide
Type `export PS1='$ '; clear`
Enter
Show

Type `# Start with a conventional API behind the gateway.`
Enter
Sleep 500ms
Type `curl -s http://127.0.0.1:8080/status -H 'Host: api.example.com' | jq '{gateway, object}'`
Enter
Sleep 2s
