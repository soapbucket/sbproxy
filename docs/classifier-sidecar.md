# Classifier Sidecar

*Last modified: 2026-08-16*

SBproxy heavily invests in out-of-process AI safety via the `sbproxy-classifier-sidecar` and `sbproxy-classifier-client` crates. These components allow you to run remote or local Machine Learning safety classifiers (e.g., prompt injection detection, PII detection, toxicity) outside of the main proxy process using gRPC.

By running classifiers in a sidecar, you achieve strict process isolation: if a learned classifier or its ONNX engine crashes, it does not take down the main proxy serving traffic.

## 1. The `InferenceService` Contract

SBproxy communicates with classifier sidecars via a protobuf contract named `InferenceService`, defined in `crates/sbproxy-classifier-proto/proto/classifier.proto`. Any gRPC service that implements this contract can be used as a classifier backend.

This contract primarily defines a `Classify` RPC. The proxy submits one text string at a time (usually a canonicalized prompt or assistant response) and gets back an array of scored labels, highest score first.

The sidecar that ships with SBproxy (`sbproxy-classifier-sidecar`) implements this contract and wraps the pure-Rust `tract` ONNX runtime. It can load `bert`-style classification models (such as a fine-tuned `deberta-v3-base` prompt-injection classifier) to evaluate traffic in real time.

## 2. Running the Sidecar

You can run the `sbproxy-classifier-sidecar` natively or inside a container. The sidecar listens on a TCP port (`--listen`, default `127.0.0.1:9440`) or a Unix Domain Socket (`--listen-uds`); the two are mutually exclusive.

### TCP listener

Point the policy's `detector_config.endpoint` at this address; that field only accepts an `http://` URL, so this is the transport the standalone `prompt_injection_v2` sidecar detector actually connects over:

```bash
cargo run -p sbproxy-classifier-sidecar -- \
  --listen 127.0.0.1:9440 \
  --model prompt-injection=/opt/models/deberta-injection.onnx:/opt/models/tokenizer.json
```

`--model` takes one `id=<model.onnx>:<tokenizer.json>` entry and is repeatable for more than one loaded classifier.

### Unix Domain Socket

`--listen-uds <path>` is the transport SBproxy's own supervised child-process wiring (`sbproxy-classifier-client`'s `Supervisor`) uses for a co-located sidecar it spawns itself. It removes the loopback TCP round trip for that pattern:

```bash
cargo run -p sbproxy-classifier-sidecar -- \
  --listen-uds /run/sbproxy/classifier.sock \
  --model prompt-injection=/opt/models/deberta-injection.onnx:/opt/models/tokenizer.json
```

## 3. Configuring the Proxy

Once your sidecar is running, select it as the detector on a `prompt_injection_v2` policy. `detector_config.endpoint` must be an `http://` URL:

```yaml
policies:
  - type: prompt_injection_v2
    threshold: 0.8
    action: block
    detector: sidecar
    detector_config:
      endpoint: http://127.0.0.1:9440
      model: prompt-injection
      injection_label: INJECTION
      timeout_ms: 250
      failure_posture: open  # a sidecar outage degrades to "clean" (allow)
```

`model` selects the loaded classifier by the id used on `--model` above (`prompt-injection` in the example). See [local-inference.md](local-inference.md#enable-first-class-onnx-prompt-injection) for the full field reference and auto-selection behavior.

## 4. Building a Custom Sidecar

Because the proxy uses a standard gRPC contract, you can build a custom sidecar in any language (Python, Go, Node.js) to run your own proprietary ML models.

To do this, you simply need to implement the `InferenceService` protobuf (located in `crates/sbproxy-classifier-proto/proto/classifier.proto`) and expose the `Classify` endpoint.

When SBproxy encounters an AI request with a sidecar-backed guardrail, it automatically:
1. Buffers and canonicalizes the request (e.g. assembling all messages into a unified prompt).
2. Connects to your sidecar via the `sbproxy-classifier-client` (which handles lazy connection and, for the supervised co-located pattern, UDS dialing).
3. Invokes `Classify` with the text payload.
4. Compares the returned score against `threshold` and either allows the request or applies the policy's `action` (`tag` or `block`).

See [guardrails.md](guardrails.md) and [prompt-injection-v2.md](prompt-injection-v2.md) for more details on wiring guardrails into your AI pipelines.
