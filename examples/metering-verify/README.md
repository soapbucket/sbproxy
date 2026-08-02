# Attested metering: receipts a buyer can verify

*Last modified: 2026-08-02*

![A metered request cuts a signed receipt, the chain verifies, one tampered entry on disk breaks it, and the verifier names the broken sequence number](../../docs/assets/metering-verify.gif)

Every request this origin serves cuts a signed receipt onto an append-only, hash-chained ledger. The chain, not the metrics, is the billing record: counters reset and aggregate, the chain proves what happened, entry by entry, and a tampered entry is caught by anyone holding the published key set. The full walkthrough is the story doc at [docs/metering.md](../../docs/metering.md).

## Run

```bash
# Clean state first: the tamper demo corrupts the chain on purpose,
# so a rerun against a stale directory starts broken.
rm -rf /tmp/sbproxy-metering

# The example ships its own upstream so metered requests carry real
# egress bytes. Start it first, then the proxy.
python3 bin/upstream.py &

sbproxy serve -f sb.yml
```

No API keys needed; the demo upstream is `bin/upstream.py`, a stdlib
HTTP server on port 8099 that answers every path with a small article.

## Meter, then verify

```bash
# Three metered requests. Each one appends a signed receipt to the chain.
for i in 1 2 3; do curl -s -o /dev/null -w '%{http_code}\n' \
     -H 'Host: api.local' http://127.0.0.1:8080/anything/article; done

# Read the chain through the operator surface.
curl -s -u admin:demo-change-me 'http://127.0.0.1:9090/api/meter/receipts?limit=3' | jq .

# Re-derive every link from genesis.
curl -s -u admin:demo-change-me -X POST http://127.0.0.1:9090/api/meter/verify | jq .
```

The verify call reports `"outcome": "ok"` with the entry count.

## Tamper test

Inflate one count in the second receipt on disk, then verify again:

```bash
python3 -c "import pathlib; p=pathlib.Path('/tmp/sbproxy-metering/receipts.ndjson'); l=p.read_text().splitlines(); l[1]=l[1].replace('\"count\":','\"count\":9',1); p.write_text('\n'.join(l)+'\n')"

curl -s -u admin:demo-change-me -X POST http://127.0.0.1:9090/api/meter/verify | jq .
```

The verdict flips to `"outcome": "broken"` and `broken_seq` names the edited entry. Changing one past receipt breaks its own digest and every link after it.

## Verify as the buyer

The operator publishes the signing key's public half as a JWKS-shaped
directory on the origin. `bin/verify-chain.py` re-derives the whole chain
from that key set alone, no SBproxy code involved:

```bash
curl -s -H 'Host: api.local' \
  http://127.0.0.1:8080/.well-known/http-message-signatures-directory > jwks.json

./bin/verify-chain.py --chain /tmp/sbproxy-metering/receipts.ndjson --jwks jwks.json
```

It prints `chain verify: OK` on an intact chain and names the first broken
sequence number on a tampered one (requires `pip install cryptography`).

## See also

- [docs/metering.md](../../docs/metering.md) - the walkthrough this example backs
- [docs/web-bot-auth.md](../../docs/web-bot-auth.md) - the signing identity and the published key directory
- [docs/ai-usage-ledger.md](../../docs/ai-usage-ledger.md) - the same chain construction, recording LLM spend
- [docs/admin-api-guide.md](../../docs/admin-api-guide.md) - admin server auth and the curl cookbook
