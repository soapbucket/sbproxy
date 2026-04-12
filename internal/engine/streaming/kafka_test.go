package streaming

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestKafkaRESTProducer_Publish(t *testing.T) {
	var receivedBody restProduceRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/topics/test-topic" {
			t.Errorf("expected /topics/test-topic, got %s", r.URL.Path)
		}
		ct := r.Header.Get("Content-Type")
		if ct != "application/vnd.kafka.binary.v2+json" {
			t.Errorf("unexpected content type: %s", ct)
		}

		if err := json.NewDecoder(r.Body).Decode(&receivedBody); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}

		resp := restProduceResponse{
			Offsets: []struct {
				Partition int   `json:"partition"`
				Offset    int64 `json:"offset"`
				ErrorCode *int  `json:"error_code,omitempty"`
				Error     string `json:"error,omitempty"`
			}{
				{Partition: 0, Offset: 42},
			},
		}
		w.Header().Set("Content-Type", "application/vnd.kafka.v2+json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	producer, err := NewKafkaRESTProducer(KafkaConfig{
		RestProxyURL: server.URL,
		Topic:        "test-topic",
	})
	if err != nil {
		t.Fatalf("failed to create producer: %v", err)
	}

	msg := Message{
		Key:   []byte("my-key"),
		Value: []byte(`{"event":"test"}`),
	}

	if err := producer.Publish(context.Background(), msg); err != nil {
		t.Fatalf("publish failed: %v", err)
	}

	if len(receivedBody.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(receivedBody.Records))
	}

	rec := receivedBody.Records[0]

	decodedValue, err := base64.StdEncoding.DecodeString(rec.Value)
	if err != nil {
		t.Fatalf("failed to decode value: %v", err)
	}
	if string(decodedValue) != `{"event":"test"}` {
		t.Errorf("unexpected value: %s", string(decodedValue))
	}

	if rec.Key == nil {
		t.Fatal("expected key to be set")
	}
	decodedKey, err := base64.StdEncoding.DecodeString(*rec.Key)
	if err != nil {
		t.Fatalf("failed to decode key: %v", err)
	}
	if string(decodedKey) != "my-key" {
		t.Errorf("unexpected key: %s", string(decodedKey))
	}
}

func TestKafkaRESTConsumer_Read(t *testing.T) {
	step := 0
	instanceID := "test-instance-1"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.kafka.v2+json")

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/consumers/test-group":
			// Create consumer instance.
			resp := restConsumerCreateResponse{
				InstanceID: instanceID,
				BaseURI:    r.Host, // Will be overridden below.
			}
			// Use the server URL for the base URI.
			resp.BaseURI = "http://" + r.Host + "/consumers/test-group/instances/" + instanceID
			json.NewEncoder(w).Encode(resp)
			step++

		case r.Method == http.MethodPost && r.URL.Path == "/consumers/test-group/instances/"+instanceID+"/subscription":
			// Subscribe.
			w.WriteHeader(http.StatusNoContent)
			step++

		case r.Method == http.MethodGet && r.URL.Path == "/consumers/test-group/instances/"+instanceID+"/records":
			// Read records.
			records := []restConsumerRecord{
				{
					Topic:     "events",
					Key:       base64.StdEncoding.EncodeToString([]byte("k1")),
					Value:     base64.StdEncoding.EncodeToString([]byte(`{"hello":"world"}`)),
					Partition: 0,
					Offset:    10,
				},
			}
			json.NewEncoder(w).Encode(records)
			step++

		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/consumers/test-group/instances/"):
			// Delete consumer instance (called by Close).
			w.WriteHeader(http.StatusNoContent)
			step++

		default:
			t.Errorf("unexpected request: %s %s (step %d)", r.Method, r.URL.Path, step)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	consumer, err := NewKafkaRESTConsumer(KafkaConfig{
		RestProxyURL:  server.URL,
		ConsumerGroup: "test-group",
	})
	if err != nil {
		t.Fatalf("failed to create consumer: %v", err)
	}
	defer consumer.Close()

	ctx := context.Background()
	if err := consumer.Subscribe(ctx, []string{"events"}); err != nil {
		t.Fatalf("subscribe failed: %v", err)
	}

	msg, err := consumer.Read(ctx)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if msg.Topic != "events" {
		t.Errorf("expected topic 'events', got %q", msg.Topic)
	}
	if string(msg.Key) != "k1" {
		t.Errorf("expected key 'k1', got %q", string(msg.Key))
	}
	if string(msg.Value) != `{"hello":"world"}` {
		t.Errorf("unexpected value: %s", string(msg.Value))
	}
	if msg.Partition != 0 {
		t.Errorf("expected partition 0, got %d", msg.Partition)
	}
	if msg.Offset != 10 {
		t.Errorf("expected offset 10, got %d", msg.Offset)
	}
}

func TestKafkaRESTProducer_PublishError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error_code":50001,"message":"internal server error"}`))
	}))
	defer server.Close()

	producer, err := NewKafkaRESTProducer(KafkaConfig{
		RestProxyURL: server.URL,
		Topic:        "test-topic",
	})
	if err != nil {
		t.Fatalf("failed to create producer: %v", err)
	}

	msg := Message{Value: []byte(`{"event":"test"}`)}
	err = producer.Publish(context.Background(), msg)
	if err == nil {
		t.Fatal("expected error from publish, got nil")
	}

	if !containsStr(err.Error(), "publish failed") {
		t.Errorf("expected error to contain 'publish failed', got: %v", err)
	}
}

func TestKafkaRESTProducer_NoRestProxyURL(t *testing.T) {
	_, err := NewKafkaRESTProducer(KafkaConfig{})
	if err == nil {
		t.Fatal("expected error when rest_proxy_url is empty")
	}
	if err != errNoRestProxyURL {
		t.Errorf("expected errNoRestProxyURL, got: %v", err)
	}
}

func TestKafkaRESTProducer_PublishAfterClose(t *testing.T) {
	producer, err := NewKafkaRESTProducer(KafkaConfig{
		RestProxyURL: "http://localhost:8082",
		Topic:        "test",
	})
	if err != nil {
		t.Fatalf("failed to create producer: %v", err)
	}

	producer.Close()

	err = producer.Publish(context.Background(), Message{Value: []byte("test")})
	if err != errProducerClosed {
		t.Errorf("expected errProducerClosed, got: %v", err)
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
