# sbproxy attested-metering verify demo. Hand-authored; recorded against
# the release binary.
#
# Regenerate with: scripts/record-tapes.sh metering-verify
# The record script starts the proxy with the config below, waits for the
# data listener, runs this tape against the live proxy, then stops it.
#
# NOTE for the recorder: run `rm -rf /tmp/sbproxy-metering` BEFORE
# scripts/record-tapes.sh. The tamper step corrupts the chain on disk on
# purpose, so a rerun against a stale state directory starts broken and
# the first verify would show `broken` instead of `ok`.
#
# CONFIG: examples/metering-verify/sb.yml
# FIXTURE: examples/metering-verify/bin/upstream.py
# FIXTURE_PORT: 8099

Output "docs/assets/metering-verify.gif"

Require curl
Require jq
Require python3

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

Type `# Three metered requests. Each one cuts a signed receipt onto this node's chain.`
Sleep 1.2s
Enter
Type `for i in 1 2 3; do curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: api.local' http://127.0.0.1:8080/anything/article; done`
Enter
Sleep 2.5s

Type `# The chain: sequence, digest, and the receipt each entry attests to.`
Enter
Type `curl -s -u admin:demo-change-me 'http://127.0.0.1:9090/api/meter/receipts?limit=3' | jq -c '.receipts[] | {seq, outcome: .claims.outcome, units: [.claims.units[] | {name, count}]}'`
Enter
Sleep 3s

Type `# Verify: every link re-derived from genesis.`
Enter
Type `curl -s -u admin:demo-change-me -X POST http://127.0.0.1:9090/api/meter/verify | jq '{outcome, entries, broken_seq}'`
Enter
Sleep 3s

Type `# Tamper with receipt 1 on disk: inflate one unit count.`
Enter
Type `python3 -c "import pathlib; p=pathlib.Path('/tmp/sbproxy-metering/receipts.ndjson'); l=p.read_text().splitlines(); l[1]=l[1].replace('\"count\":','\"count\":9',1); p.write_text('\n'.join(l)+'\n')"`
Enter
Sleep 1.6s

Type `# Verify again: the chain names the broken link.`
Enter
Type `curl -s -u admin:demo-change-me -X POST http://127.0.0.1:9090/api/meter/verify | jq '{outcome, broken_seq, reason}'`
Enter
Sleep 4s
