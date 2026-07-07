# sbproxy example cassette: use-case-coding-assistant.
# Regenerate with: scripts/record-tapes.sh use-case-coding-assistant
#
# CONFIG: examples/use-case-coding-assistant/sb.yml
# REQUIRES: gpu-l4

Output "docs/assets/use-case-coding-assistant.gif"

Require curl
Require jq

Set Shell "bash"
Set FontSize 16
Set Width 1280
Set Height 600
Set Padding 24
Set TypingSpeed 30ms
Set Theme { "name": "sbproxy", "background": "#0d0d0f", "foreground": "#e6e6e6", "cursor": "#ffb454", "selection": "#2a2a33", "black": "#1a1a1f", "red": "#ff6b6b", "green": "#a8d96a", "yellow": "#ffb454", "blue": "#7aa2f7", "magenta": "#bb9af7", "cyan": "#7dcfff", "white": "#e6e6e6", "brightBlack": "#5c5c66", "brightRed": "#ff8888", "brightGreen": "#c3f088", "brightYellow": "#ffd194", "brightBlue": "#9bb8ff", "brightMagenta": "#d4b8ff", "brightCyan": "#a4e0ff", "brightWhite": "#ffffff" }

Hide
Type `export PS1='$ '; clear`
Enter
Show

Type `# glm-4-flash is running on this box's GPU under the name claude-sonnet-4-5.`
Sleep 1.4s
Enter
Sleep 500ms

Type `curl -s localhost:8080/v1/messages -H 'Content-Type: application/json' -d '{"model":"claude-sonnet-4-5","max_tokens":100,"messages":[{"role":"user","content":"One sentence: where are you running?"}]}' | jq -r '.model, .content[0].text'`
Enter
Sleep 5s

Type `# Same gateway on the OpenAI wire, for Cline and Continue.`
Enter
Type `curl -s localhost:8080/v1/chat/completions -H 'Content-Type: application/json' -d '{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"One sentence: what are you really?"}]}' | jq -r '.choices[0].message.content'`
Enter
Sleep 5s

Type `# Claude Code needs only the base URL.`
Enter
Type `export ANTHROPIC_BASE_URL=http://localhost:8080`
Enter
Sleep 2.5s
