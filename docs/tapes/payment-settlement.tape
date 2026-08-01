# sbproxy payment settlement cassette: the price, the challenge, and the
# closed failure path in front of a paid route.
#
# Regenerate with:  scripts/record-tapes.sh payment-settlement
# The record script starts `sbproxy serve -f examples/rail-x402-base-sepolia/sb.yml`,
# waits for the port, runs this tape against the live proxy, then stops it.
# Nothing here uses a wallet, a facilitator credential, a provider key, or a
# funded address, and no secret is typed on screen. Record it with
# SBPROXY_DEMO_ENV=/dev/null so the recording cannot pick up a local key file.
# Requires vhs, ttyd, ffmpeg, curl (brew install vhs).
#
# CONFIG: examples/rail-x402-base-sepolia/sb.yml

Output "docs/assets/payment-settlement.gif"

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

Type `# A reader is never charged. The request goes straight to the origin.`
Enter
Sleep 400ms

Type `curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: blog.test.sbproxy.dev' http://127.0.0.1:8080/article`
Enter
Sleep 2s

Type `# A declared crawler gets a price instead of the article.`
Enter
Sleep 400ms

Type `curl -is -H 'Host: blog.test.sbproxy.dev' -H 'User-Agent: GPTBot/1.0' http://127.0.0.1:8080/article | head -n 10`
Enter
Sleep 3s

Type `# A credential the proxy never issued buys nothing, and the origin is not called.`
Enter
Sleep 400ms

Type `curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: blog.test.sbproxy.dev' -H 'User-Agent: GPTBot/1.0' -H 'crawler-payment: not-a-token-this-proxy-issued' http://127.0.0.1:8080/article`
Enter
Sleep 2.5s

Type `# Only a payment this proxy recorded as settled opens the route.`
Enter
Sleep 2s
