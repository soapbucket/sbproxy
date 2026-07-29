# Credential-free enterprise AI gateway: OpenAI-compatible AI traffic.
#
# CONFIG: examples/enterprise-ai-gateway/sb.yml
# AUX_CONFIG: examples/enterprise-ai-gateway/upstream.yml

Output "docs/assets/enterprise-ai-gateway-ai.gif"

Require curl
Require jq

Set Shell "bash"
Set FontSize 15
Set Width 1400
Set Height 560
Set Padding 24
Set TypingSpeed 18ms
Set Theme { "name": "sbproxy", "background": "#0d0d0f", "foreground": "#e6e6e6", "cursor": "#ffb454", "selection": "#2a2a33", "black": "#1a1a1f", "red": "#ff6b6b", "green": "#a8d96a", "yellow": "#ffb454", "blue": "#7aa2f7", "magenta": "#bb9af7", "cyan": "#7dcfff", "white": "#e6e6e6", "brightBlack": "#5c5c66", "brightRed": "#ff8888", "brightGreen": "#c3f088", "brightYellow": "#ffd194", "brightBlue": "#9bb8ff", "brightMagenta": "#d4b8ff", "brightCyan": "#7dcfff", "brightWhite": "#ffffff" }

Hide
Type `export PS1='$ '; clear`
Enter
Show

Type `# Add an OpenAI-compatible AI origin without changing the listener.`
Enter
Sleep 500ms
Type `curl -s http://127.0.0.1:8080/v1/chat/completions -H 'Host: ai.example.com' -H 'Content-Type: application/json' -d '{"model":"local-demo","messages":[{"role":"user","content":"Say hello."}]}' | jq '{object, model, answer: .choices[0].message.content}'`
Enter
Sleep 2.5s
