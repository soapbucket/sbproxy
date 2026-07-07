# sbproxy local-first hybrid demo. Recorded against the release binary.
#
# Regenerate with:  scripts/record-tapes.sh use-case-local-first
# Keys are sourced from the environment by the record script and never typed.
# Requires vhs, ttyd, ffmpeg, curl, jq (brew install vhs jq).
# The local lane spawns a real inference engine, so this tape records on a
# GPU host as part of certification, not on the docs box.
#
# CONFIG: examples/use-case-local-first/sb.yml
# REQUIRES: gpu-l4
# LOGLEVEL: warn

Output "docs/assets/use-case-local-first.gif"

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

Type `# Local first: the GPU on this box answers, in the same OpenAI shape as any hosted call.`
Sleep 1.4s
Enter
Sleep 500ms

Type `curl -s localhost:8080/v1/chat/completions -H 'Host: ai.local' -d '{"model":"qwen3-14b","messages":[{"role":"user","content":"In one sentence, what is a reverse proxy?"}]}' | jq -r '(.model|split("/")|last), .choices[0].message.content'`
Enter
Sleep 16s

Type `# A training-sensitive prompt may only land on providers marked no_prompt_training: here, only local.`
Enter
Type `curl -s localhost:8080/v1/chat/completions -H 'Host: ai.local' -H 'x-sbproxy-disallow-prompt-training: true' -d '{"model":"qwen3-14b","messages":[{"role":"user","content":"Summarize this internal memo in one line: Q3 margins improved."}]}' | jq -r '.model|split("/")|last'`
Enter
Sleep 14s

Type `# Both lanes land in one tamper-evident ledger. The split, then the dollars the GPU displaced:`
Enter
Type `jq -r '.event.provider' /tmp/sb-local-first-ledger.jsonl | sort | uniq -c`
Enter
Sleep 2.5s

Type `jq -s '[ .[] | select(.event.provider=="local") | .event ] | {local_calls: length, displaced_usd: ((map(.prompt_tokens) | add // 0) / 1e6 * 0.15 + (map(.completion_tokens) | add // 0) / 1e6 * 0.60)}' /tmp/sb-local-first-ledger.jsonl`
Enter
Sleep 5s
