# sbproxy multi-provider failover demo. Recorded against the release binary.
#
# Regenerate with:  scripts/record-tapes.sh ai-fallback
# Keys are sourced from the environment by the record script and never typed.
# Requires vhs, ttyd, ffmpeg, curl, jq (brew install vhs jq).
#
# CONFIG: examples/ai-routing-fallback/sb.yml
# LOGLEVEL: warn

Output "docs/assets/ai-fallback.gif"

Require curl
Require jq

Set Shell "bash"
Set FontSize 16
Set Width 1280
Set Height 620
Set Padding 24
Set TypingSpeed 30ms
Set Theme { "name": "sbproxy", "background": "#0d0d0f", "foreground": "#e6e6e6", "cursor": "#ffb454", "selection": "#2a2a33", "black": "#1a1a1f", "red": "#ff6b6b", "green": "#a8d96a", "yellow": "#ffb454", "blue": "#7aa2f7", "magenta": "#bb9af7", "cyan": "#7dcfff", "white": "#e6e6e6", "brightBlack": "#5c5c66", "brightRed": "#ff8888", "brightGreen": "#c3f088", "brightYellow": "#ffd194", "brightBlue": "#9bb8ff", "brightMagenta": "#d4b8ff", "brightCyan": "#a4e0ff", "brightWhite": "#ffffff" }

Hide
Type `export PS1='$ '; clear`
Enter
Show

Type `# fallback_chain: the primary provider is down. One request, no client-side retries.`
Sleep 1.4s
Enter
Sleep 500ms

Type `curl -s localhost:8080/v1/chat/completions -H 'Host: ai.local' -d '{"model":"claude-haiku-4-5","messages":[{"role":"user","content":"In one sentence, what is a reverse proxy?"}]}' | jq -r '.model, .choices[0].message.content'`
Enter
Sleep 4s

Type `# The client got a clean answer. Under the hood the primary failed and the backup served it:`
Enter
Type `grep -o 'AI proxy: upstream request failed.*attempt=[0-9]*' /tmp/sbproxy-rec.log | head -1`
Enter
Sleep 4s
