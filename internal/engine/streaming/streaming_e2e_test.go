package streaming

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestStreaming_FullPipeline_E2E tests the Kafka REST Proxy streaming flow end-to-end
// through producer, consumer, and mediator components using mock HTTP servers.
func TestStreaming_FullPipeline_E2E(t *testing.T) {
	t.Run("producer publishes message to mock REST proxy", func(t *testing.T) {
		var receivedBody restProduceRequest
		var receivedPath string
		var receivedContentType string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedPath = r.URL.Path
			receivedContentType = r.Header.Get("Content-Type")

			if err := json.NewDecoder(r.Body).Decode(&receivedBody); err != nil {
				t.Errorf("failed to decode produce request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "application/vnd.kafka.v2+json")
			json.NewEncoder(w).Encode(restProduceResponse{
				Offsets: []struct {
					Partition int   `json:"partition"`
					Offset    int64 `json:"offset"`
					ErrorCode *int  `json:"error_code,omitempty"`
					Error     string `json:"error,omitempty"`
				}{
					{Partition: 0, Offset: 100},
				},
			})
		}))
		defer server.Close()

		producer, err := NewKafkaRESTProducer(KafkaConfig{
			RestProxyURL: server.URL,
			Topic:        "orders",
		})
		if err != nil {
			t.Fatalf("failed to create producer: %v", err)
		}
		defer producer.Close()

		msg := Message{
			Key:   []byte("order-456"),
			Value: []byte(`{"action":"created","total":149.99}`),
		}

		if err := producer.Publish(context.Background(), msg); err != nil {
			t.Fatalf("publish failed: %v", err)
		}

		// Verify the request was sent correctly.
		if receivedPath != "/topics/orders" {
			t.Errorf("expected path /topics/orders, got %s", receivedPath)
		}
		if receivedContentType != "application/vnd.kafka.binary.v2+json" {
			t.Errorf("expected binary content type, got %s", receivedContentType)
		}
		if len(receivedBody.Records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(receivedBody.Records))
		}

		decodedValue, err := base64.StdEncoding.DecodeString(receivedBody.Records[0].Value)
		if err != nil {
			t.Fatalf("failed to decode value: %v", err)
		}
		if string(decodedValue) != `{"action":"created","total":149.99}` {
			t.Errorf("unexpected value: %s", string(decodedValue))
		}

		if receivedBody.Records[0].Key == nil {
			t.Fatal("expected key to be set")
		}
		decodedKey, err := base64.StdEncoding.DecodeString(*receivedBody.Records[0].Key)
		if err != nil {
			t.Fatalf("failed to decode key: %v", err)
		}
		if string(decodedKey) != "order-456" {
			t.Errorf("expected key order-456, got %s", string(decodedKey))
		}
	})

	t.Run("consumer subscribes and reads messages from mock REST proxy", func(t *testing.T) {
		instanceID := "e2e-instance-1"
		var step atomic.Int32

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/vnd.kafka.v2+json")

			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/consumers/e2e-group":
				// Create consumer instance.
				step.Add(1)
				resp := restConsumerCreateResponse{
					InstanceID: instanceID,
					BaseURI:    "http://" + r.Host + "/consumers/e2e-group/instances/" + instanceID,
				}
				json.NewEncoder(w).Encode(resp)

			case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/subscription"):
				// Subscribe to topics.
				step.Add(1)
				var subReq restSubscriptionRequest
				if err := json.NewDecoder(r.Body).Decode(&subReq); err != nil {
					t.Errorf("failed to decode subscription request: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if len(subReq.Topics) != 1 || subReq.Topics[0] != "events" {
					t.Errorf("expected subscription to [events], got %v", subReq.Topics)
				}
				w.WriteHeader(http.StatusNoContent)

			case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/records"):
				// Read records.
				step.Add(1)
				records := []restConsumerRecord{
					{
						Topic:     "events",
						Key:       base64.StdEncoding.EncodeToString([]byte("event-key")),
						Value:     base64.StdEncoding.EncodeToString([]byte(`{"type":"user.created","id":"u-123"}`)),
						Partition: 0,
						Offset:    42,
					},
				}
				json.NewEncoder(w).Encode(records)

			case r.Method == http.MethodDelete:
				// Delete consumer (called by Close).
				step.Add(1)
				w.WriteHeader(http.StatusNoContent)

			default:
				t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		consumer, err := NewKafkaRESTConsumer(KafkaConfig{
			RestProxyURL:  server.URL,
			ConsumerGroup: "e2e-group",
		})
		if err != nil {
			t.Fatalf("failed to create consumer: %v", err)
		}

		ctx := context.Background()

		// Subscribe.
		if err := consumer.Subscribe(ctx, []string{"events"}); err != nil {
			t.Fatalf("subscribe failed: %v", err)
		}

		// Read a message.
		msg, err := consumer.Read(ctx)
		if err != nil {
			t.Fatalf("read failed: %v", err)
		}

		if msg.Topic != "events" {
			t.Errorf("expected topic 'events', got %q", msg.Topic)
		}
		if string(msg.Key) != "event-key" {
			t.Errorf("expected key 'event-key', got %q", string(msg.Key))
		}
		if string(msg.Value) != `{"type":"user.created","id":"u-123"}` {
			t.Errorf("unexpected value: %s", string(msg.Value))
		}
		if msg.Partition != 0 {
			t.Errorf("expected partition 0, got %d", msg.Partition)
		}
		if msg.Offset != 42 {
			t.Errorf("expected offset 42, got %d", msg.Offset)
		}

		// Close the consumer.
		if err := consumer.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}
	})

	t.Run("mediator HTTPToStream publishes through producer to mock", func(t *testing.T) {
		var receivedBody restProduceRequest

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/topics/analytics" {
				t.Errorf("expected /topics/analytics, got %s", r.URL.Path)
			}

			if err := json.NewDecoder(r.Body).Decode(&receivedBody); err != nil {
				t.Errorf("failed to decode request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "application/vnd.kafka.v2+json")
			json.NewEncoder(w).Encode(restProduceResponse{
				Offsets: []struct {
					Partition int   `json:"partition"`
					Offset    int64 `json:"offset"`
					ErrorCode *int  `json:"error_code,omitempty"`
					Error     string `json:"error,omitempty"`
				}{
					{Partition: 0, Offset: 200},
				},
			})
		}))
		defer server.Close()

		producer, err := NewKafkaRESTProducer(KafkaConfig{
			RestProxyURL: server.URL,
		})
		if err != nil {
			t.Fatalf("failed to create producer: %v", err)
		}

		// Use a mock consumer (not needed for HTTPToStream).
		consumer := &mockConsumer{}
		mediator := NewMediator(producer, consumer, nil)
		defer mediator.Close()

		key := []byte("page-view-789")
		value := []byte(`{"page":"/home","duration_ms":3200}`)
		headers := map[string]string{"X-Trace-ID": "trace-abc-123"}

		err = mediator.HTTPToStream(context.Background(), "analytics", key, value, headers)
		if err != nil {
			t.Fatalf("HTTPToStream failed: %v", err)
		}

		// Verify the produce request was formed correctly.
		if len(receivedBody.Records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(receivedBody.Records))
		}

		decodedValue, err := base64.StdEncoding.DecodeString(receivedBody.Records[0].Value)
		if err != nil {
			t.Fatalf("failed to decode value: %v", err)
		}
		if string(decodedValue) != `{"page":"/home","duration_ms":3200}` {
			t.Errorf("unexpected value: %s", string(decodedValue))
		}
	})

	t.Run("mediator HTTPToStream with validation rejects invalid payload", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("REST proxy should not be called when validation fails")
		}))
		defer server.Close()

		producer, err := NewKafkaRESTProducer(KafkaConfig{
			RestProxyURL: server.URL,
			Topic:        "validated-topic",
		})
		if err != nil {
			t.Fatalf("failed to create producer: %v", err)
		}

		validator := &failingValidator{err: errPublishFailed}
		consumer := &mockConsumer{}
		mediator := NewMediator(producer, consumer, validator)
		defer mediator.Close()

		err = mediator.HTTPToStream(context.Background(), "validated-topic", nil, []byte(`bad`), nil)
		if err == nil {
			t.Fatal("expected validation error, got nil")
		}
	})

	t.Run("producer with SASL auth sends Basic auth header", func(t *testing.T) {
		var receivedUsername string
		var receivedPassword string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, p, ok := r.BasicAuth()
			if ok {
				receivedUsername = u
				receivedPassword = p
			}

			w.Header().Set("Content-Type", "application/vnd.kafka.v2+json")
			json.NewEncoder(w).Encode(restProduceResponse{
				Offsets: []struct {
					Partition int   `json:"partition"`
					Offset    int64 `json:"offset"`
					ErrorCode *int  `json:"error_code,omitempty"`
					Error     string `json:"error,omitempty"`
				}{
					{Partition: 0, Offset: 1},
				},
			})
		}))
		defer server.Close()

		producer, err := NewKafkaRESTProducer(KafkaConfig{
			RestProxyURL: server.URL,
			Topic:        "authed-topic",
			SASLUsername: "kafka-user",
			SASLPassword: "kafka-pass",
		})
		if err != nil {
			t.Fatalf("failed to create producer: %v", err)
		}
		defer producer.Close()

		err = producer.Publish(context.Background(), Message{Value: []byte(`{"test":true}`)})
		if err != nil {
			t.Fatalf("publish failed: %v", err)
		}

		if receivedUsername != "kafka-user" {
			t.Errorf("expected username kafka-user, got %q", receivedUsername)
		}
		if receivedPassword != "kafka-pass" {
			t.Errorf("expected password kafka-pass, got %q", receivedPassword)
		}
	})

	t.Run("producer publish error propagates correctly", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error_code":50001,"message":"broker not available"}`))
		}))
		defer server.Close()

		producer, err := NewKafkaRESTProducer(KafkaConfig{
			RestProxyURL: server.URL,
			Topic:        "error-topic",
		})
		if err != nil {
			t.Fatalf("failed to create producer: %v", err)
		}
		defer producer.Close()

		err = producer.Publish(context.Background(), Message{Value: []byte(`{"event":"test"}`)})
		if err == nil {
			t.Fatal("expected error from publish, got nil")
		}
		if !strings.Contains(err.Error(), "publish failed") {
			t.Errorf("expected error to contain 'publish failed', got: %v", err)
		}
	})

	t.Run("consumer operations after close return error", func(t *testing.T) {
		consumer, err := NewKafkaRESTConsumer(KafkaConfig{
			RestProxyURL:  "http://localhost:9999",
			ConsumerGroup: "closed-group",
		})
		if err != nil {
			t.Fatalf("failed to create consumer: %v", err)
		}

		consumer.Close()

		err = consumer.Subscribe(context.Background(), []string{"topic"})
		if err != errConsumerClosed {
			t.Errorf("expected errConsumerClosed from Subscribe, got: %v", err)
		}

		_, err = consumer.Read(context.Background())
		if err != errConsumerClosed {
			t.Errorf("expected errConsumerClosed from Read, got: %v", err)
		}
	})

	t.Run("full round trip: produce then consume", func(t *testing.T) {
		instanceID := "roundtrip-instance"
		var producedValue string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/vnd.kafka.v2+json")

			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/topics/roundtrip":
				// Produce endpoint: capture the produced value.
				var body restProduceRequest
				json.NewDecoder(r.Body).Decode(&body)
				if len(body.Records) > 0 {
					producedValue = body.Records[0].Value
				}

				json.NewEncoder(w).Encode(restProduceResponse{
					Offsets: []struct {
						Partition int   `json:"partition"`
						Offset    int64 `json:"offset"`
						ErrorCode *int  `json:"error_code,omitempty"`
						Error     string `json:"error,omitempty"`
					}{
						{Partition: 0, Offset: 500},
					},
				})

			case r.Method == http.MethodPost && r.URL.Path == "/consumers/roundtrip-group":
				// Create consumer.
				json.NewEncoder(w).Encode(restConsumerCreateResponse{
					InstanceID: instanceID,
					BaseURI:    "http://" + r.Host + "/consumers/roundtrip-group/instances/" + instanceID,
				})

			case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/subscription"):
				w.WriteHeader(http.StatusNoContent)

			case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/records"):
				// Return the same value that was produced.
				val := producedValue
				if val == "" {
					val = base64.StdEncoding.EncodeToString([]byte("fallback"))
				}
				records := []restConsumerRecord{
					{
						Topic:     "roundtrip",
						Key:       base64.StdEncoding.EncodeToString([]byte("rt-key")),
						Value:     val,
						Partition: 0,
						Offset:    500,
					},
				}
				json.NewEncoder(w).Encode(records)

			case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/offsets"):
				// Commit offsets.
				w.WriteHeader(http.StatusOK)

			case r.Method == http.MethodDelete:
				w.WriteHeader(http.StatusNoContent)

			default:
				t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		ctx := context.Background()

		// Produce a message.
		producer, err := NewKafkaRESTProducer(KafkaConfig{
			RestProxyURL: server.URL,
		})
		if err != nil {
			t.Fatalf("failed to create producer: %v", err)
		}

		originalPayload := `{"round":"trip","seq":1}`
		err = producer.Publish(ctx, Message{
			Topic: "roundtrip",
			Key:   []byte("rt-key"),
			Value: []byte(originalPayload),
		})
		if err != nil {
			t.Fatalf("produce failed: %v", err)
		}
		producer.Close()

		// Consume the message.
		consumer, err := NewKafkaRESTConsumer(KafkaConfig{
			RestProxyURL:  server.URL,
			ConsumerGroup: "roundtrip-group",
		})
		if err != nil {
			t.Fatalf("failed to create consumer: %v", err)
		}

		if err := consumer.Subscribe(ctx, []string{"roundtrip"}); err != nil {
			t.Fatalf("subscribe failed: %v", err)
		}

		msg, err := consumer.Read(ctx)
		if err != nil {
			t.Fatalf("read failed: %v", err)
		}

		if string(msg.Value) != originalPayload {
			t.Errorf("expected value %q, got %q", originalPayload, string(msg.Value))
		}
		if string(msg.Key) != "rt-key" {
			t.Errorf("expected key rt-key, got %q", string(msg.Key))
		}
		if msg.Topic != "roundtrip" {
			t.Errorf("expected topic roundtrip, got %q", msg.Topic)
		}
		if msg.Offset != 500 {
			t.Errorf("expected offset 500, got %d", msg.Offset)
		}

		// Commit the message.
		if err := consumer.Commit(ctx, msg); err != nil {
			t.Fatalf("commit failed: %v", err)
		}

		consumer.Close()
	})
}
