# sbproxy clustered dynamic key management demo: two replicas, the mesh
# distributed cache in front of a shared Redis store. A key minted on one
# replica is instantly usable on the other, and a revoke propagates, with no
# config reload. Resolution order is L1 in-memory cache, then the mesh cache,
# then Redis as the source of truth.
#
# Regenerate with:  scripts/record-tapes.sh ai-dynamic-keys-cluster
# The record script starts node A (the config below) and waits for readiness;
# this tape then launches node B on the next ports, drives the cross-replica
# lifecycle against both admin APIs, and stops node B at the end.
#
# Prerequisites: a local Redis on port 6399 (redis-server --port 6399 &) and
# vhs, ttyd, ffmpeg, curl, jq. Node B is launched with the same binary the
# record script used (SBPROXY_BIN, default ./target/release/sbproxy).
#
# CONFIG: docs/tapes/configs/ai-dynamic-keys-cluster.sb.yml

Output "docs/assets/ai-dynamic-keys-cluster.gif"

Require curl
Require jq

Set Shell "bash"
Set FontSize 16
Set Width 1280
Set Height 720
Set Padding 24
Set TypingSpeed 30ms
Set Theme { "name": "sbproxy", "background": "#0d0d0f", "foreground": "#e6e6e6", "cursor": "#ffb454", "selection": "#2a2a33", "black": "#1a1a1f", "red": "#ff6b6b", "green": "#a8d96a", "yellow": "#ffb454", "blue": "#7aa2f7", "magenta": "#bb9af7", "cyan": "#7dcfff", "white": "#e6e6e6", "brightBlack": "#5c5c66", "brightRed": "#ff8888", "brightGreen": "#c3f088", "brightYellow": "#ffd194", "brightBlue": "#9bb8ff", "brightMagenta": "#d4b8ff", "brightCyan": "#a4e0ff", "brightWhite": "#ffffff" }

# Start node B (the second replica) in the background and let gossip converge.
Hide
Type `export PS1='$ '`
Enter
Type `BIN=${SBPROXY_BIN:-./target/release/sbproxy}; RUST_LOG=error NO_COLOR=1 $BIN docs/tapes/configs/ai-dynamic-keys-cluster-node-b.sb.yml >/tmp/sbproxy-tape-nodeb.log 2>&1 & echo $! >/tmp/sbproxy-tape-nodeb.pid`
Enter
Type `sleep 4; clear`
Enter
Show

Type `# Two replicas: node A admin on :9090, node B admin on :9091.`
Sleep 1.4s
Enter
Type `# Mesh cache in front, Redis as the shared source of truth.`
Sleep 1.4s
Enter
Sleep 400ms

Type `KID=$(curl -s -u admin:admin -X POST localhost:9090/admin/keys -d '{"name":"fleet-key","max_requests_per_minute":120,"allowed_models":["gpt-4o-mini"]}' | jq -r '.key.key_id'); echo "minted $KID on node A"`
Enter
Sleep 2.2s

Type `# Same key, read from node B. It never touched node B's config.`
Sleep 1.2s
Enter
Sleep 400ms

Type `curl -s -u admin:admin localhost:9091/admin/keys/$KID | jq '.key | {key_id, name, status, source}'`
Enter
Sleep 2.5s

Type `# Revoke on node A...`
Sleep 1s
Enter
Sleep 300ms

Type `curl -s -u admin:admin -X POST localhost:9090/admin/keys/$KID/revoke | jq '.key | {key_id, status}'`
Enter
Sleep 2.2s

Type `# ...and node B already sees it revoked. Clusterwide, no reload.`
Sleep 1.2s
Enter
Sleep 400ms

Type `curl -s -u admin:admin localhost:9091/admin/keys/$KID | jq '.key | {key_id, status}'`
Enter
Sleep 3s

Hide
Type `kill $(cat /tmp/sbproxy-tape-nodeb.pid) 2>/dev/null`
Enter
Show
