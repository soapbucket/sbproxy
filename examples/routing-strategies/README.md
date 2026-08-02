# Routing strategies, against upstreams that say who they are

![Routing strategies, against upstreams that say who they are](../../docs/assets/routing-strategies.gif)

The runnable half of [docs/routing-strategies.md](../../docs/routing-strategies.md). A registered `RoutingStrategy` runs before the load balancer's configured `algorithm` and picks from the already-filtered eligible targets. Which target it picked is invisible when every target is the same address, so this example ships two replicas that report their own name.

Three origins share that pair, one per documented behaviour:

| Origin | Strategy | What it shows |
|---|---|---|
| `gpu.local` | `gpu-aware` | Picks the lowest valid `metadata.gpu_utilization` |
| `percent.local` | `gpu-aware` | An out-of-range signal is ignored, so the round-robin fallback runs |
| `lora.local` | `lora-aware` | Prefers a replica advertising the requested adapter, defers when none does |

## Run

```bash
# The example ships its own two upstreams. Start them first.
python3 examples/routing-strategies/fixture.py &
make run CONFIG=examples/routing-strategies/sb.yml
```

Or under compose, which is what the smoke runner uses:

```bash
cd examples/routing-strategies
docker compose up -d --wait
```

## Test

`gpu-aware` reads the number an operator put in `metadata` and picks the lowest one. It does not poll GPUs and it does not drift, so the answer is the same every time until the metadata changes:

```bash
for i in 1 2 3 4; do curl -s -H 'Host: gpu.local' http://127.0.0.1:8080/infer; echo; done
```

```
{"target":"replica-b","path":"/infer","adapter_requested":""}
{"target":"replica-b","path":"/infer","adapter_requested":""}
{"target":"replica-b","path":"/infer","adapter_requested":""}
{"target":"replica-b","path":"/infer","adapter_requested":""}
```

`percent.local` carries the same key with values of `72` and `31`, which is the percent-versus-fraction typo. Both are outside `[0.0, 1.0]`, so the strategy ignores them instead of treating a busy replica as the least loaded one, and falls back to a round robin across the healthy slice:

```bash
for i in 1 2 3 4; do curl -s -H 'Host: percent.local' http://127.0.0.1:8080/infer; echo; done
```

```
{"target":"replica-a","path":"/infer","adapter_requested":""}
{"target":"replica-b","path":"/infer","adapter_requested":""}
{"target":"replica-a","path":"/infer","adapter_requested":""}
{"target":"replica-b","path":"/infer","adapter_requested":""}
```

`lora-aware` prefers the replica that already has the requested adapter warm. The hint rides on `X-LoRA-Adapter` or `?adapter=`:

```bash
curl -s -H 'Host: lora.local' -H 'X-LoRA-Adapter: alice-tone' http://127.0.0.1:8080/infer; echo
curl -s -H 'Host: lora.local' -H 'X-LoRA-Adapter: carol-voice' http://127.0.0.1:8080/infer; echo
```

```
{"target":"replica-a","path":"/infer","adapter_requested":"alice-tone"}
{"target":"replica-b","path":"/infer","adapter_requested":"carol-voice"}
```

Ask for an adapter nobody advertises and the strategy returns no selection rather than inventing one. `algorithm: least_connections` picks from the same eligible slice:

```bash
curl -s -H 'Host: lora.local' -H 'X-LoRA-Adapter: nobody-has-this' http://127.0.0.1:8080/infer
```

```
{"target":"replica-a","path":"/infer","adapter_requested":"nobody-has-this"}
```

Run the checked smoke cases from the repository root with:

```bash
bash scripts/examples-smoke.sh examples/routing-strategies
```

## Clean up

```bash
docker compose down -v
```

## Read more

- [docs/routing-strategies.md](../../docs/routing-strategies.md) - the trait, the registration pattern, and every shipped strategy
- [examples/lora-aware-routing/](../lora-aware-routing/) - the three-replica adapter-inventory config, without the local upstreams
- [examples/load-balancer/](../load-balancer/) - the plain algorithm-only pool
