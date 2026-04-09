// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"fmt"
	"time"

	json "github.com/goccy/go-json"
)

// ResponseToChat converts a CreateResponseRequest into a ChatCompletionRequest
// for execution through the existing chat completions pipeline.
func ResponseToChat(req *CreateResponseRequest, store ResponseStore) (*ChatCompletionRequest, error) {
	chatReq := &ChatCompletionRequest{
		Model:       req.Model,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		Tools:       req.Tools,
	}

	if req.MaxOutputTokens > 0 {
		chatReq.MaxTokens = &req.MaxOutputTokens
	}

	if req.Stream {
		stream := true
		chatReq.Stream = &stream
	}

	var messages []Message

	// Prepend instructions as system message
	if req.Instructions != "" {
		messages = append(messages, mustTextMessage("system", req.Instructions))
	}

	// If previous_response_id is set, prepend the previous conversation context
	if req.PreviousResponseID != "" && store != nil {
		prev, err := store.Get(nil, req.PreviousResponseID)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch previous response %q: %w", req.PreviousResponseID, err)
		}
		if prev != nil {
			// Reconstruct the previous conversation: input messages + output
			prevMessages := responsesToMessages(prev)
			messages = append(messages, prevMessages...)
		}
	}

	// Parse input: string or []Message
	inputMessages, err := parseResponseInput(req.Input)
	if err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}
	messages = append(messages, inputMessages...)

	chatReq.Messages = messages
	return chatReq, nil
}

// parseResponseInput parses the polymorphic "input" field of CreateResponseRequest.
// It can be a plain string (converted to a user message) or an array of messages.
func parseResponseInput(input json.RawMessage) ([]Message, error) {
	if len(input) == 0 {
		return nil, nil
	}

	// Try string first
	var s string
	if err := json.Unmarshal(input, &s); err == nil {
		return []Message{mustTextMessage("user", s)}, nil
	}

	// Try array of messages
	var msgs []Message
	if err := json.Unmarshal(input, &msgs); err == nil {
		return msgs, nil
	}

	// Try array of generic objects (like ResponsesInputMessages does)
	var messageList []map[string]any
	if err := json.Unmarshal(input, &messageList); err == nil {
		var out []Message
		for _, item := range messageList {
			role, _ := item["role"].(string)
			if role == "" {
				role = "user"
			}
			switch content := item["content"].(type) {
			case string:
				out = append(out, mustTextMessage(role, content))
			case []any:
				raw, merr := json.Marshal(content)
				if merr == nil {
					out = append(out, Message{Role: role, Content: raw})
				}
			case map[string]any:
				raw, merr := json.Marshal(content)
				if merr == nil {
					out = append(out, Message{Role: role, Content: raw})
				}
			}
		}
		return out, nil
	}

	return nil, fmt.Errorf("input must be a string or array of messages")
}

// responsesToMessages reconstructs chat messages from a ResponseObject's output.
func responsesToMessages(resp *ResponseObject) []Message {
	var msgs []Message
	for _, item := range resp.Output {
		if item.Type == "message" && len(item.Content) > 0 {
			var text string
			for _, c := range item.Content {
				if c.Type == "output_text" || c.Type == "text" {
					text += c.Text
				}
			}
			if text != "" {
				msgs = append(msgs, mustTextMessage(item.Role, text))
			}
		}
	}
	return msgs
}

// ChatToResponse converts a ChatCompletionResponse into a ResponseObject.
func ChatToResponse(chatResp *ChatCompletionResponse, req *CreateResponseRequest) *ResponseObject {
	resp := &ResponseObject{
		ID:        "resp_" + chatResp.ID,
		Object:    "response",
		CreatedAt: time.Now().Unix(),
		Model:     chatResp.Model,
		Status:    ResponseStatusCompleted,
		Metadata:  req.Metadata,
	}

	if req.PreviousResponseID != "" {
		resp.PreviousResponseID = req.PreviousResponseID
	}

	// Map choices to output items
	for _, choice := range chatResp.Choices {
		outputItem := OutputItem{
			Type: "message",
			ID:   "msg_" + chatResp.ID,
			Role: choice.Message.Role,
		}

		// Extract text content
		text := choice.Message.ContentString()
		if text != "" {
			outputItem.Content = append(outputItem.Content, ContentItem{
				Type: "output_text",
				Text: text,
			})
		}

		// Map tool calls to function_call output items
		for _, tc := range choice.Message.ToolCalls {
			resp.Output = append(resp.Output, OutputItem{
				Type: "function_call",
				ID:   tc.ID,
				Content: []ContentItem{
					{
						Type: "function_call",
						Text: tc.Function.Arguments,
					},
				},
			})
		}

		if len(outputItem.Content) > 0 {
			resp.Output = append(resp.Output, outputItem)
		}

		// Map finish reason to status
		if choice.FinishReason != nil {
			switch *choice.FinishReason {
			case "stop":
				resp.Status = ResponseStatusCompleted
			case "length":
				resp.Status = ResponseStatusCompleted
			case "content_filter":
				resp.Status = ResponseStatusFailed
				resp.Error = &ResponseError{
					Code:    "content_filter",
					Message: "Content was filtered by the provider.",
				}
			}
		}
	}

	// Copy usage
	if chatResp.Usage != nil {
		resp.Usage = &ResponseUsage{
			InputTokens:  chatResp.Usage.PromptTokens,
			OutputTokens: chatResp.Usage.CompletionTokens,
			TotalTokens:  chatResp.Usage.TotalTokens,
		}
		if chatResp.Usage.PromptTokensCached > 0 {
			resp.Usage.InputDetails = &ResponseUsageInputDetails{
				CachedTokens: chatResp.Usage.PromptTokensCached,
			}
		}
	}

	return resp
}
