# sbproxy dynamic key management demo: virtual keys as a live, governed
# resource. Mint, list, rotate, and revoke inbound keys at runtime through the
# admin API, with no config reload.
#
# Regenerate with:  scripts/record-tapes.sh ai-dynamic-keys
# The record script starts sbproxy with the config below, waits for readiness,
# runs this tape against the live admin API, then stops it. The recording config
# uses inline demo crypto so it boots with no environment setup; the runnable
# user-facing example is examples/ai-dynamic-keys/.
# Requires vhs, ttyd, ffmpeg, curl, jq (brew install vhs jq).
#
# CONFIG: docs/tapes/configs/ai-dynamic-keys.sb.yml

Output "docs/assets/ai-dynamic-keys.gif"

Require curl
Require jq

Set Shell "bash"
Set FontSize 16
Set Width 1280
Set Height 760
Set Padding 24
Set TypingSpeed 30ms
Set Theme { "name": "sbproxy", "background": "#0d0d0f", "foreground": "#e6e6e6", "cursor": "#ffb454", "selection": "#2a2a33", "black": "#1a1a1f", "red": "#ff6b6b", "green": "#a8d96a", "yellow": "#ffb454", "blue": "#7aa2f7", "magenta": "#bb9af7", "cyan": "#7dcfff", "white": "#e6e6e6", "brightBlack": "#5c5c66", "brightRed": "#ff8888", "brightGreen": "#c3f088", "brightYellow": "#ffd194", "brightBlue": "#9bb8ff", "brightMagenta": "#d4b8ff", "brightCyan": "#a4e0ff", "brightWhite": "#ffffff" }

Hide
Type `export PS1='$ '; clear`
Enter
Show

Type `# Mint a virtual key at runtime. The plaintext token comes back once.`
Sleep 1.4s
Enter
Sleep 400ms

Type `curl -s -u admin:admin -X POST localhost:9090/admin/keys -d '{"name":"ci-runner","max_requests_per_minute":60,"allowed_models":["gpt-4o-mini"]}' | jq '{token, key: {key_id: .key.key_id, name: .key.name, status: .key.status, rpm: .key.max_requests_per_minute}}'`
Enter
Sleep 2.5s

Type `# List keys. No secret ever leaves the store; only the public key_id does.`
Sleep 1.2s
Enter
Sleep 400ms

Type `curl -s -u admin:admin localhost:9090/admin/keys | jq '.keys | map({key_id, name, status})'`
Enter
Sleep 2.5s

Type `# Rotate a key: a fresh secret, old one still valid for a grace window.`
Sleep 1.2s
Enter
Sleep 400ms

Type `curl -s -u admin:admin -X POST localhost:9090/admin/keys/seed0001/rotate -d '{"grace_secs":3600}' | jq '{token, grace_expires_at, key_id: .key.key_id}'`
Enter
Sleep 2.5s

Type `# Revoke is instant. The next request with that key is denied, no reload.`
Sleep 1.2s
Enter
Sleep 400ms

Type `curl -s -u admin:admin -X POST localhost:9090/admin/keys/seed0001/revoke | jq '.key | {key_id, status}'`
Enter
Sleep 3s
