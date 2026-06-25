# sbproxy hedged / raced dispatch demo. Recorded against the release binary.
#
# Regenerate with:  scripts/record-tapes.sh ai-race-routing
# The record script starts `sbproxy examples/ai-race-routing/sb.yml`
# (with provider keys from the environment), waits for readiness, runs this
# tape against the live proxy, then stops it. Keys are never typed on screen.
# Requires vhs, ttyd, ffmpeg, curl, jq (brew install vhs jq).
#
# CONFIG: examples/ai-race-routing/sb.yml

Output "docs/assets/ai-race-routing.gif"

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

Type `# routing: race -> fan one request out to every provider, keep the first 2xx.`
Sleep 1.4s
Enter
Sleep 500ms

Type `curl -s localhost:8080/v1/chat/completions -H 'Host: ai.local' -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"In one sentence, what is tail latency?"}]}' | jq -r '.model, .choices[0].message.content'`
Enter
Sleep 4s

Type `# The slow racer was cancelled; the winner answered. Lower tail latency,`
Enter
Type `# at the cost of a duplicate upstream call.`
Sleep 2s
Enter
