# Extension inventory proof, recorded against the real release binary.
#
# Regenerate with: scripts/record-tapes.sh extension-inventory
# The record script starts the valid bundle config, waits for the real proxy,
# runs this tape against the authenticated admin API, then stops the process.
#
# CONFIG: docs/tapes/configs/extension-inventory.sb.yml

Output "docs/assets/extension-inventory.gif"

Require curl
Require jq

Set Shell "bash"
Set FontSize 16
Set Width 1280
Set Height 820
Set Padding 24
Set TypingSpeed 28ms
Set Theme { "name": "sbproxy", "background": "#0d0d0f", "foreground": "#e6e6e6", "cursor": "#ffb454", "selection": "#2a2a33", "black": "#1a1a1f", "red": "#ff6b6b", "green": "#a8d96a", "yellow": "#ffb454", "blue": "#7aa2f7", "magenta": "#bb9af7", "cyan": "#7dcfff", "white": "#e6e6e6", "brightBlack": "#5c5c66", "brightRed": "#ff8888", "brightGreen": "#c3f088", "brightYellow": "#ffd194", "brightBlue": "#9bb8ff", "brightMagenta": "#d4b8ff", "brightCyan": "#a4e0ff", "brightWhite": "#ffffff" }

Hide
Type `export PS1='$ '; export SB='./target/release/sbproxy'; clear`
Enter
Show

Type `# The admin API is pinned to the running pipeline generation.`
Enter
Sleep 500ms
Type `curl -s -u "admin:$SB_ADMIN_PASSWORD" http://127.0.0.1:19090/api/extensions | jq '{scope, summary, bundles: [.bundles[] | {name, state, source, runtime, load}], hooks: [.hooks[] | {kind, match_key, state, position}]}'`
Enter
Sleep 4s

Type `# Doctor loads the same bundle, but never claims that it is running.`
Enter
Sleep 500ms
Type `$SB doctor docs/tapes/configs/extension-inventory.sb.yml | sed -n '/^extensions$/,/^$/p'`
Enter
Sleep 7s

Type `# A bad manifest stays visible as a bounded failed inventory record.`
Enter
Sleep 500ms
Type `$SB doctor docs/tapes/configs/extension-inventory-broken.sb.yml | sed -n '/^extensions$/,/^$/p'`
Enter
Sleep 7s
