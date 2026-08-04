# Classifier Sidecar

SBproxy heavily invests in out-of-process AI safety via the `sbproxy-classifier-sidecar` and `sbproxy-classifier-client` crates. These components allow you to run remote or local Machine Learning safety classifiers (e.g., prompt injection detection, PII detection, toxicity) outside of the main proxy process using gRPC.

By running classifiers in a sidecar, you achieve strict process isolation: if a learned classifier or its ONNX engine crashes, it does not take down the main proxy serving traffic.

## 1. The `InferenceService` Contract

SBproxy communicates with classifier sidecars via a protobuf contract named `InferenceService`. Any gRPC service that implements this contract can be used as a classifier backend.

This contract primarily defines a `Classify` RPC. The proxy submits an array of text strings (usually canonicalized prompts or assistant responses) and expects an array of scoring verdicts back.

The sidecar that ships with SBproxy (`sbproxy-classifier-sidecar`) implements this contract and wraps the pure-Rust `tract` ONNX runtime. It can load `bert`-style classification models (like `ProtectAI/deberta-v3-base-injection`) to evaluate traffic in real-time.

## 2. Running the Sidecar

You can run the `sbproxy-classifier-sidecar` natively or inside a container. The sidecar listens on a Unix Domain Socket (UDS) or a TCP port.

### Unix Domain Socket (Recommended)

Running over UDS is highly recommended for co-located sidecars as it avoids TCP overhead.

```bash
cargo run -p sbproxy-classifier-sidecar -- \
  --listen-uds /run/sbproxy/classifier.sock \
  --model-path /opt/models/deberta-injection.onnx \
  --tokenizer-path /opt/models/tokenizer.json \
  --token-model "bert:512"
```

### TCP Listener

If the sidecar is hosted on another machine or container, you can bind it to a TCP port:

```bash
cargo run -p sbproxy-classifier-sidecar -- \
  --listen-tcp 0.0.0.0:50051 \
  --model-path /opt/models/deberta-injection.onnx \
  --tokenizer-path /opt/models/tokenizer.json \
  --token-model "bert:512"
```

## 3. Configuring the Proxy

Once your sidecar is running, configure SBproxy to use it via the `classifiers` block in your `sb.yml`.

```yaml
ai_proxy:
  classifiers:
    - name: injection-sidecar
      type: grpc
      # Use unix:// for UDS or http:// for TCP
      endpoint: "unix:///run/sbproxy/classifier.sock"
      timeout_ms: 100
      
  guardrails:
    input:
      prompt_injection_v2:
        enforcement_mode: block
        detector: sidecar
        classifier_ref: injection-sidecar
        threshold: 0.95
```

## 4. Building a Custom Sidecar

Because the proxy uses a standard gRPC contract, you can build a custom sidecar in any language (Python, Go, Node.js) to run your own proprietary ML models.

To do this, you simply need to implement the `InferenceService` protobuf (located in `crates/sbproxy-classifier-proto/proto/classifier.proto`) and expose the `Classify` endpoint.

When SBproxy encounters an AI request with a sidecar-backed guardrail, it automatically:
1. Buffers and canonicalizes the request (e.g. assembling all messages into a unified prompt).
2. Connects to your sidecar via the `sbproxy-classifier-client` (which handles supervised UDS lazy-loading and connection pooling).
3. Invokes `Classify` with the text payload.
4. Uses your sidecar's returned verdict and threshold score to either `release` or `block` the request.

See [ai-guardrails.md](ai-guardrails.md) and [prompt-injection-v2.md](prompt-injection-v2.md) for more details on wiring guardrails into your AI pipelines.
