# sbproxy "own OpenRouter" demo: one governed endpoint in front of OpenAI and
# Anthropic. Mint a virtual key at runtime, call both vendors through the one
# endpoint with it, read the hash-chained spend ledger, and trip the key's
# daily budget cap.
#
# Regenerate with:  scripts/record-tapes.sh use-case-own-openrouter
# The record script starts `sbproxy examples/use-case-own-openrouter/sb.yml`
# (provider keys from the environment), waits for readiness, runs this tape
# against the live proxy, then stops it. Provider keys are never typed on
# screen; the only visible token is the throwaway virtual key minted here.
# Requires vhs, ttyd, ffmpeg, curl, jq (brew install vhs jq).
#
# CONFIG: examples/use-case-own-openrouter/sb.yml

Output "docs/assets/use-case-own-openrouter.gif"

Require curl
Require jq

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

Type `# Mint a virtual key for one team. The plaintext token comes back once.`
Sleep 1.2s
Enter
Sleep 400ms

Type `TOKEN=$(curl -s -u admin:admin -X POST localhost:9090/admin/keys -d '{"name":"team-payments"}' | jq -r .token) && echo "team-payments: $TOKEN"`
Enter
Sleep 2.5s

Type `# One endpoint, the model field picks the vendor. First OpenAI...`
Enter
Type `curl -s localhost:8080/v1/chat/completions -H 'Host: ai.local' -H "Authorization: Bearer $TOKEN" -d '{"model":"gpt-4o-mini","max_tokens":48,"messages":[{"role":"user","content":"One sentence: why route LLM calls through a gateway?"}]}' | jq -r '.model, .choices[0].message.content'`
Enter
Sleep 4s

Type `# ...then Anthropic. Same endpoint, same team key.`
Enter
Type `curl -s localhost:8080/v1/chat/completions -H 'Host: ai.local' -H "Authorization: Bearer $TOKEN" -d '{"model":"claude-haiku-4-5","max_tokens":220,"messages":[{"role":"user","content":"In about 120 words, why should every team get its own AI gateway key?"}]}' | jq -r '.model // .error.message'`
Enter
Sleep 4.5s

Type `# Both calls are in the hash-chained spend ledger, attributed to the key.`
Enter
Type `tail -n 2 /tmp/sbproxy-own-openrouter-ledger.jsonl | jq -c '{provider: .event.provider, model: .event.model, tokens: .event.total_tokens, cost_usd: .event.cost_usd, key: .event.key_id}'`
Enter
Sleep 3.5s

Type `# The key carries a tiny daily budget. It is spent, so the next call is refused.`
Enter
Type `curl -is localhost:8080/v1/chat/completions -H 'Host: ai.local' -H "Authorization: Bearer $TOKEN" -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"one more?"}]}' | sed -n '1p;$p'`
Enter
Sleep 4s
