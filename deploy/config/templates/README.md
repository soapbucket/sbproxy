# Config Templates

Pre-built configuration templates for common proxy deployment patterns. Copy a template, customize the values, and deploy.

## Templates

### secure_ai_gateway.json

Full security stack for AI proxy traffic. Combines WAF (with prompt injection rules), IP allowlisting, PII detection/masking, rate limiting, CORS, and security headers. Suited for production deployments where AI traffic must pass through the complete security pipeline.

Key features:
- WAF with fail-closed behavior and prompt injection detection
- Input guardrails: PII masking, injection blocking, secrets blocking
- Output guardrails: PII masking on responses
- IP allowlisting restricted to private network ranges
- Weighted routing across providers with retry logic
- Per-workspace and per-API-key budget enforcement

### ide_gateway.json

Optimized for IDE-based code completion tools (Cursor, Claude Code, Cline, GitHub Copilot, Zed). Higher rate limits, permissive CORS for local development, semantic caching for repeated completions, and fallback chain routing for reliability.

Key features:
- Higher rate limits (120 req/min with burst of 20) for rapid completions
- Fallback chain routing (tries providers in order on failure)
- Semantic cache with 0.98 similarity threshold to deduplicate near-identical requests
- Session tracking for multi-turn conversations
- Metadata-only logging (no request/response body storage)
- Budget enforcement in log-only mode (does not block requests)

## Usage

1. Copy a template to your sites directory:
   ```
   cp templates/ide_gateway.json sites/my-ide-gateway.json
   ```

2. Update the `hostname` field to match your domain.

3. Replace variable placeholders with actual values or set the corresponding environment variables.

4. Adjust policy thresholds (rate limits, budget caps, IP ranges) for your workload.

## Variable Substitution

Templates use `${ENV_VAR}` placeholders for sensitive values. These are resolved at runtime from environment variables. Common variables:

| Variable | Description |
|---|---|
| `${OPENAI_API_KEY}` | OpenAI API key for the openai provider |
| `${ANTHROPIC_API_KEY}` | Anthropic API key for the anthropic provider |

Set these in your deployment environment or secrets manager before starting the proxy.
