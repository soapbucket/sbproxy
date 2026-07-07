# sbproxy serve-on-L4 preflight demo. Recorded against the release binary on a
# machine with NO GPU, on purpose: the CPU-recordable half of the story is the
# fit planner's preflight (validate, plan, doctor) refusing what this box
# cannot run. First token on the L4 itself is the Run it section of
# docs/use-case-serve-on-l4.md.
#
# Regenerate with:  scripts/record-tapes.sh use-case-serve-on-l4
# The record script starts `sbproxy examples/use-case-serve-on-l4/sb.yml`,
# waits for readiness, runs this tape, then stops it. LOGLEVEL is warn so the
# serve: preflight warning lands in /tmp/sbproxy-rec.log for the grep below.
# Requires vhs, ttyd, ffmpeg, curl (brew install vhs).
#
# CONFIG: examples/use-case-serve-on-l4/sb.yml
# LOGLEVEL: warn

Output "docs/assets/use-case-serve-on-l4.gif"

Require curl

Set Shell "bash"
Set FontSize 16
Set Width 1280
Set Height 820
Set Padding 24
Set TypingSpeed 30ms
Set Theme { "name": "sbproxy", "background": "#0d0d0f", "foreground": "#e6e6e6", "cursor": "#ffb454", "selection": "#2a2a33", "black": "#1a1a1f", "red": "#ff6b6b", "green": "#a8d96a", "yellow": "#ffb454", "blue": "#7aa2f7", "magenta": "#bb9af7", "cyan": "#7dcfff", "white": "#e6e6e6", "brightBlack": "#5c5c66", "brightRed": "#ff8888", "brightGreen": "#c3f088", "brightYellow": "#ffd194", "brightBlue": "#9bb8ff", "brightMagenta": "#d4b8ff", "brightCyan": "#a4e0ff", "brightWhite": "#ffffff" }

Hide
Type `export PS1='$ '; sbproxy() { "${SBPROXY_BIN:-./target/release/sbproxy}" "$@"; }; clear`
Enter
Show

Type `# One model in a serve: block. Before anything spawns, the config gets checked.`
Sleep 1.4s
Enter
Sleep 400ms

Type `sbproxy validate examples/use-case-serve-on-l4/sb.yml`
Enter
Sleep 2s

Type `sbproxy plan -f examples/use-case-serve-on-l4/sb.yml`
Enter
Sleep 2.5s

Type `clear`
Enter

Type `# The engine doctor: can THIS box serve the model? (This one cannot: no GPU.)`
Sleep 1.4s
Enter
Sleep 400ms

Type `sbproxy doctor`
Enter
Sleep 6s

Type `# The gateway still boots; the preflight names the blocker in the log instead.`
Sleep 1.4s
Enter
Sleep 400ms

Type `grep -o 'serve: is configured but no GPU is visible.*' /tmp/sbproxy-rec.log | head -1`
Enter
Sleep 4s

Type `# On the L4 the verdict flips to ready, and the planner picks FP8 for the card.`
Sleep 3s
Enter
