# sbproxy semantic cache demo. Recorded against the release binary.
#
# Regenerate with:  scripts/record-tapes.sh semantic-cache
# Keys are sourced from the environment by the record script and never typed.
# Requires vhs, ttyd, ffmpeg, curl, jq (brew install vhs jq).
#
# CONFIG: examples/semantic-cache-openai/sb.yml

Output "docs/assets/semantic-cache.gif"

Require curl

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

Type `# Semantic cache: matches on meaning, not exact text. First ask is a MISS.`
Sleep 1.4s
Enter
Sleep 500ms

Type `curl -s -D - -o /dev/null localhost:8080/v1/chat/completions -H 'Host: ai.local' -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"What are the benefits of caching?"}]}' -w 'roundtrip=%{time_total}s\n' | grep -iE 'x-semcache|roundtrip'`
Enter
Sleep 4s

Type `# Now a reworded prompt. Different words, same meaning -> served from cache.`
Enter
Type `curl -s -D - -o /dev/null localhost:8080/v1/chat/completions -H 'Host: ai.local' -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Summarize the benefits of caching."}]}' -w 'roundtrip=%{time_total}s\n' | grep -iE 'x-semcache|roundtrip'`
Enter
Sleep 3s

Type `# x-semcache: HIT - the slow completion is skipped, at zero provider cost.`
Enter
Sleep 2s
