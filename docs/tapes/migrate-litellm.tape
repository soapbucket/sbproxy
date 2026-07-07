# sbproxy LiteLLM migration demo. Recorded against the release binary.
#
# Regenerate with:  scripts/record-tapes.sh migrate-litellm
# The record script starts `sbproxy examples/migrate-litellm/sb.yml` (with
# provider keys from the environment), waits for readiness, runs this tape
# against the live proxy, then stops it. On camera the tape re-runs the
# importer on the LiteLLM config from the same example dir, writing to /tmp
# so the committed sb.yml is untouched. Keys are never typed on screen.
# Requires vhs, ttyd, ffmpeg, curl, jq (brew install vhs jq).
#
# CONFIG: examples/migrate-litellm/sb.yml

Output "docs/assets/migrate-litellm.gif"

Require curl
Require jq

Set Shell "bash"
Set FontSize 16
Set Width 1280
Set Height 820
Set Padding 24
Set TypingSpeed 30ms
Set Theme { "name": "sbproxy", "background": "#0d0d0f", "foreground": "#e6e6e6", "cursor": "#ffb454", "selection": "#2a2a33", "black": "#1a1a1f", "red": "#ff6b6b", "green": "#a8d96a", "yellow": "#ffb454", "blue": "#7aa2f7", "magenta": "#bb9af7", "cyan": "#7dcfff", "white": "#e6e6e6", "brightBlack": "#5c5c66", "brightRed": "#ff8888", "brightGreen": "#c3f088", "brightYellow": "#ffd194", "brightBlue": "#9bb8ff", "brightMagenta": "#d4b8ff", "brightCyan": "#a4e0ff", "brightWhite": "#ffffff" }

Hide
Type `export PS1='$ '; sbproxy() { ${SBPROXY_BIN:-./target/release/sbproxy} "$@"; }; clear`
Enter
Show

Type `# One command translates a LiteLLM config.yaml into an sbproxy sb.yml.`
Sleep 1.4s
Enter
Sleep 400ms

Type `sbproxy config import-litellm examples/migrate-litellm/config.yaml --out /tmp/sb.yml`
Enter
Sleep 3s

Type `# Unmapped keys become warnings, never silent drops. Here is the result:`
Enter
Type `head -n 16 /tmp/sb.yml`
Enter
Sleep 4s

Type `# The proxy is already serving the migrated config. Same clients, same API:`
Enter
Type `curl -s localhost:8080/v1/chat/completions -H 'Host: ai.local' -d '{"model":"gpt-4","messages":[{"role":"user","content":"In one sentence: why translate a proxy config with a tool instead of by hand?"}]}' | jq -r '.model, .choices[0].message.content'`
Enter
Sleep 5s
