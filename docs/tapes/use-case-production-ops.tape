# sbproxy production-ops demo. Recorded against the release binary.
#
# Regenerate with:  scripts/record-tapes.sh use-case-production-ops
# The record script starts `sbproxy examples/use-case-production-ops/sb.yml`,
# waits for readiness, runs this tape against the live proxy, then stops it.
# The config is self-contained: the healthy origin is a mock, the failing
# origins point at a dead local port, so no network or keys are needed.
# Requires vhs, ttyd, ffmpeg, curl (brew install vhs).
#
# CONFIG: examples/use-case-production-ops/sb.yml
# LOGLEVEL: warn,access_log=info

Output "docs/assets/use-case-production-ops.gif"

Require curl

Set Shell "bash"
Set FontSize 16
Set Width 1280
Set Height 820
Set Padding 24
Set TypingSpeed 30ms
Set Theme { "name": "sbproxy", "background": "#0d0d0f", "foreground": "#e6e6e6", "cursor": "#ffb454", "selection": "#2a2a33", "black": "#1a1a1f", "red": "#ff6b6b", "green": "#a8d96a", "yellow": "#ffb454", "blue": "#7aa2f7", "magenta": "#bb9af7", "cyan": "#7dcfff", "white": "#e6e6e6", "brightBlack": "#5c5c66", "brightRed": "#ff8888", "brightGreen": "#c3f088", "brightYellow": "#ffd194", "brightBlue": "#9bb8ff", "brightMagenta": "#d4b8ff", "brightCyan": "#a4e0ff", "brightWhite": "#ffffff" }

Hide
Type `export PS1='$ '; clear`
Enter
Show

Type `# One healthy origin, one whose upstream just died (dead local port).`
Sleep 1.2s
Enter
Sleep 400ms

Type `curl -s -H 'Host: app.local' http://127.0.0.1:8080/`
Enter
Sleep 1.5s

Type `curl -s -o /dev/null -w 'checkout.local -> HTTP %{http_code}\n' -H 'Host: checkout.local' http://127.0.0.1:8080/`
Enter
Sleep 1.5s

Type `# payments.local hits the same dead port, but declares a fallback origin:`
Enter
Type `curl -s -H 'Host: payments.local' http://127.0.0.1:8080/`
Enter
Sleep 1.8s

Type `# Evidence for the on-call: the 502 is already a counter on /metrics...`
Enter
Type `curl -s http://127.0.0.1:8080/metrics | grep 'sbproxy_requests_total{'`
Enter
Sleep 2.5s

Type `# ...and every request left one JSON access-log line.`
Enter
Type `grep -o '{"timestamp.*' /tmp/sbproxy-rec.log | grep '"origin":"checkout.local"' | tail -n 1`
Enter
Sleep 4s
