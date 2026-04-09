// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"net/http"
	"strings"
)

const openAIInsecureAPIKeySubprotocolPrefix = "openai-insecure-api-key."

func websocketSubprotocols(r *http.Request) []string {
	if r == nil {
		return nil
	}

	raw := r.Header.Values("Sec-WebSocket-Protocol")
	if len(raw) == 0 {
		if header := r.Header.Get("Sec-WebSocket-Protocol"); header != "" {
			raw = []string{header}
		}
	}

	var protocols []string
	for _, value := range raw {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				protocols = append(protocols, part)
			}
		}
	}

	return protocols
}

func extractOpenAIKeyFromSubprotocols(r *http.Request) string {
	for _, protocol := range websocketSubprotocols(r) {
		if strings.HasPrefix(protocol, openAIInsecureAPIKeySubprotocolPrefix) {
			return strings.TrimPrefix(protocol, openAIInsecureAPIKeySubprotocolPrefix)
		}
	}
	return ""
}
