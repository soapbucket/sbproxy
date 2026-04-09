package providers

import json "github.com/goccy/go-json"

func mustJSON(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}
