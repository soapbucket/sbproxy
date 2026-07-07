# sbproxy use-case cassette: meter and monetize AI crawlers.
# Regenerate with: scripts/record-tapes.sh use-case-meter-crawlers
#
# Money shots: an unsigned crawler is challenged (401), a signed but
# unpaid crawler gets the 402 price challenge, a token redeems once
# (200), and the replay is charged again (402). The signing key written
# in the hidden block is the public RFC 8032 test vector that matches
# the demo `public_key` in the example config; it is not a secret.
#
# CONFIG: examples/use-case-meter-crawlers/sb.yml

Output "docs/assets/use-case-meter-crawlers.gif"

Require curl
Require jq
Require openssl

Set Shell "bash"
Set FontSize 16
Set Width 1280
Set Height 600
Set Padding 24
Set TypingSpeed 30ms
Set Theme { "name": "sbproxy", "background": "#0d0d0f", "foreground": "#e6e6e6", "cursor": "#ffb454", "selection": "#2a2a33", "black": "#1a1a1f", "red": "#ff6b6b", "green": "#a8d96a", "yellow": "#ffb454", "blue": "#7aa2f7", "magenta": "#bb9af7", "cyan": "#7dcfff", "white": "#e6e6e6", "brightBlack": "#5c5c66", "brightRed": "#ff8888", "brightGreen": "#c3f088", "brightYellow": "#ffd194", "brightBlue": "#9bb8ff", "brightMagenta": "#d4b8ff", "brightCyan": "#a4e0ff", "brightWhite": "#ffffff" }

Hide
Type `export PS1='$ '; printf -- '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE KEY-----\n' > /tmp/wba-demo-key.pem; clear`
Enter
Show

Type `# Unverified crawler: no RFC 9421 signature, challenged at the door.`
Enter
Type `curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: blog.local' -H 'User-Agent: GPTBot/1.0' http://127.0.0.1:8080/anything/article`
Enter
Sleep 1.6s

Type `# Sign the request as GPTBot (Web Bot Auth demo key).`
Enter
Type `eval $(examples/web-bot-auth/bin/sign-request.sh --key /tmp/wba-demo-key.pem --keyid openai-2026-01 --method GET --target-uri /anything/article --authority blog.local)`
Enter
Sleep 1s

Type `# Verified but unpaid: the 402 challenge names the price and the retry header.`
Enter
Type `curl -s -H 'Host: blog.local' -H 'User-Agent: GPTBot/1.0' -H "Signature-Input: $SIG_INPUT" -H "Signature: $SIG" http://127.0.0.1:8080/anything/article | jq .`
Enter
Sleep 2s

Type `# Pay with a token: served. Each token redeems exactly once.`
Enter
Type `curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: blog.local' -H 'User-Agent: GPTBot/1.0' -H "Signature-Input: $SIG_INPUT" -H "Signature: $SIG" -H 'crawler-payment: demo-tok-001' http://127.0.0.1:8080/anything/article`
Enter
Sleep 1.6s

Type `curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: blog.local' -H 'User-Agent: GPTBot/1.0' -H "Signature-Input: $SIG_INPUT" -H "Signature: $SIG" -H 'crawler-payment: demo-tok-001' http://127.0.0.1:8080/anything/article`
Enter
Sleep 2s
