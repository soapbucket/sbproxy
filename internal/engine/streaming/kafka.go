// kafka.go implements Kafka producer and consumer via the Kafka REST Proxy.
package streaming

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// KafkaConfig holds the configuration for Kafka REST Proxy connections.
type KafkaConfig struct {
	Brokers           []string `json:"brokers"`
	Topic             string   `json:"topic"`
	ConsumerGroup     string   `json:"consumer_group,omitempty"`
	RestProxyURL      string   `json:"rest_proxy_url,omitempty"`
	SchemaRegistryURL string   `json:"schema_registry_url,omitempty"`
	TLS               bool     `json:"tls,omitempty"`
	SASLMechanism     string   `json:"sasl_mechanism,omitempty"`
	SASLUsername      string   `json:"sasl_username,omitempty"`
	SASLPassword      string   `json:"sasl_password,omitempty"`
}

// restProducerRecord is a single record in a Kafka REST Proxy produce request.
type restProducerRecord struct {
	Key   *string `json:"key,omitempty"`
	Value string  `json:"value"`
}

// restProduceRequest is the body for a Kafka REST Proxy produce call.
type restProduceRequest struct {
	Records []restProducerRecord `json:"records"`
}

// restProduceResponse is the response from a Kafka REST Proxy produce call.
type restProduceResponse struct {
	Offsets []struct {
		Partition int    `json:"partition"`
		Offset    int64  `json:"offset"`
		ErrorCode *int   `json:"error_code,omitempty"`
		Error     string `json:"error,omitempty"`
	} `json:"offsets"`
}

// restConsumerCreateRequest is the body for creating a consumer instance.
type restConsumerCreateRequest struct {
	Name             string `json:"name,omitempty"`
	Format           string `json:"format"`
	AutoOffsetReset  string `json:"auto.offset.reset"`
	AutoCommitEnable string `json:"auto.commit.enable"`
}

// restConsumerCreateResponse is the response when creating a consumer instance.
type restConsumerCreateResponse struct {
	InstanceID string `json:"instance_id"`
	BaseURI    string `json:"base_uri"`
}

// restSubscriptionRequest is the body for subscribing to topics.
type restSubscriptionRequest struct {
	Topics []string `json:"topics"`
}

// restConsumerRecord is a single record returned by the consumer.
type restConsumerRecord struct {
	Topic     string `json:"topic"`
	Key       string `json:"key"`
	Value     string `json:"value"`
	Partition int    `json:"partition"`
	Offset    int64  `json:"offset"`
}

// restCommitOffset is a single offset in a commit request.
type restCommitOffset struct {
	Topic     string `json:"topic"`
	Partition int    `json:"partition"`
	Offset    int64  `json:"offset"`
}

// restCommitRequest is the body for committing offsets.
type restCommitRequest struct {
	Offsets []restCommitOffset `json:"offsets"`
}

var (
	errNoRestProxyURL = errors.New("streaming: rest_proxy_url is required")
	errNoTopic        = errors.New("streaming: topic is required")
	errProducerClosed = errors.New("streaming: producer is closed")
	errConsumerClosed = errors.New("streaming: consumer is closed")
	errPublishFailed  = errors.New("streaming: publish failed")
	errNotSubscribed  = errors.New("streaming: consumer has not subscribed to any topics")
)

// KafkaRESTProducer publishes messages via Kafka REST Proxy.
type KafkaRESTProducer struct {
	config KafkaConfig
	client *http.Client
	closed bool
	mu     sync.Mutex
}

// NewKafkaRESTProducer creates a new KafkaRESTProducer.
func NewKafkaRESTProducer(config KafkaConfig) (*KafkaRESTProducer, error) {
	if config.RestProxyURL == "" {
		return nil, errNoRestProxyURL
	}
	config.RestProxyURL = strings.TrimRight(config.RestProxyURL, "/")
	return &KafkaRESTProducer{
		config: config,
		client: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Publish sends a message to the configured topic via the Kafka REST Proxy.
func (p *KafkaRESTProducer) Publish(ctx context.Context, msg Message) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return errProducerClosed
	}
	p.mu.Unlock()

	topic := msg.Topic
	if topic == "" {
		topic = p.config.Topic
	}
	if topic == "" {
		return errNoTopic
	}

	record := restProducerRecord{
		Value: base64.StdEncoding.EncodeToString(msg.Value),
	}
	if len(msg.Key) > 0 {
		k := base64.StdEncoding.EncodeToString(msg.Key)
		record.Key = &k
	}

	body := restProduceRequest{
		Records: []restProducerRecord{record},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("streaming: failed to marshal produce request: %w", err)
	}

	url := fmt.Sprintf("%s/topics/%s", p.config.RestProxyURL, topic)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("streaming: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/vnd.kafka.binary.v2+json")
	req.Header.Set("Accept", "application/vnd.kafka.v2+json")
	p.setAuth(req)

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("streaming: REST proxy request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%w: status %d, body: %s", errPublishFailed, resp.StatusCode, string(respBody))
	}

	var produceResp restProduceResponse
	if err := json.NewDecoder(resp.Body).Decode(&produceResp); err != nil {
		return fmt.Errorf("streaming: failed to decode produce response: %w", err)
	}

	for _, o := range produceResp.Offsets {
		if o.ErrorCode != nil && *o.ErrorCode != 0 {
			return fmt.Errorf("%w: partition %d error: %s", errPublishFailed, o.Partition, o.Error)
		}
	}

	return nil
}

// Close shuts down the producer.
func (p *KafkaRESTProducer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

func (p *KafkaRESTProducer) setAuth(req *http.Request) {
	if p.config.SASLUsername != "" && p.config.SASLPassword != "" {
		req.SetBasicAuth(p.config.SASLUsername, p.config.SASLPassword)
	}
}

// KafkaRESTConsumer reads messages via Kafka REST Proxy.
type KafkaRESTConsumer struct {
	config     KafkaConfig
	client     *http.Client
	instanceID string
	baseURI    string
	subscribed bool
	closed     bool
	mu         sync.Mutex
}

// NewKafkaRESTConsumer creates a new KafkaRESTConsumer.
func NewKafkaRESTConsumer(config KafkaConfig) (*KafkaRESTConsumer, error) {
	if config.RestProxyURL == "" {
		return nil, errNoRestProxyURL
	}
	if config.ConsumerGroup == "" {
		config.ConsumerGroup = "soapbucket-default"
	}
	config.RestProxyURL = strings.TrimRight(config.RestProxyURL, "/")
	return &KafkaRESTConsumer{
		config: config,
		client: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Subscribe creates a consumer instance and subscribes to the given topics.
func (c *KafkaRESTConsumer) Subscribe(ctx context.Context, topics []string) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errConsumerClosed
	}
	c.mu.Unlock()

	// Step 1: Create consumer instance.
	createBody := restConsumerCreateRequest{
		Format:           "binary",
		AutoOffsetReset:  "earliest",
		AutoCommitEnable: "false",
	}
	payload, err := json.Marshal(createBody)
	if err != nil {
		return fmt.Errorf("streaming: failed to marshal consumer create request: %w", err)
	}

	url := fmt.Sprintf("%s/consumers/%s", c.config.RestProxyURL, c.config.ConsumerGroup)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("streaming: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/vnd.kafka.v2+json")
	c.setAuth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("streaming: consumer create failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("streaming: consumer create failed: status %d, body: %s", resp.StatusCode, string(respBody))
	}

	var createResp restConsumerCreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&createResp); err != nil {
		return fmt.Errorf("streaming: failed to decode consumer create response: %w", err)
	}

	c.mu.Lock()
	c.instanceID = createResp.InstanceID
	c.baseURI = strings.TrimRight(createResp.BaseURI, "/")
	c.mu.Unlock()

	// Step 2: Subscribe to topics.
	subBody := restSubscriptionRequest{Topics: topics}
	payload, err = json.Marshal(subBody)
	if err != nil {
		return fmt.Errorf("streaming: failed to marshal subscription request: %w", err)
	}

	subURL := fmt.Sprintf("%s/subscription", c.baseURI)
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, subURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("streaming: failed to create subscription request: %w", err)
	}
	req.Header.Set("Content-Type", "application/vnd.kafka.v2+json")
	c.setAuth(req)

	resp2, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("streaming: subscription failed: %w", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode < 200 || resp2.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp2.Body, 4096))
		return fmt.Errorf("streaming: subscription failed: status %d, body: %s", resp2.StatusCode, string(respBody))
	}

	c.mu.Lock()
	c.subscribed = true
	c.mu.Unlock()

	return nil
}

// Read fetches the next message from the subscribed topics.
func (c *KafkaRESTConsumer) Read(ctx context.Context) (Message, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return Message{}, errConsumerClosed
	}
	if !c.subscribed {
		c.mu.Unlock()
		return Message{}, errNotSubscribed
	}
	baseURI := c.baseURI
	c.mu.Unlock()

	url := fmt.Sprintf("%s/records", baseURI)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Message{}, fmt.Errorf("streaming: failed to create read request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.kafka.binary.v2+json")
	c.setAuth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return Message{}, fmt.Errorf("streaming: read request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Message{}, fmt.Errorf("streaming: read failed: status %d, body: %s", resp.StatusCode, string(respBody))
	}

	var records []restConsumerRecord
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return Message{}, fmt.Errorf("streaming: failed to decode records: %w", err)
	}

	if len(records) == 0 {
		return Message{}, io.EOF
	}

	rec := records[0]
	value, err := base64.StdEncoding.DecodeString(rec.Value)
	if err != nil {
		return Message{}, fmt.Errorf("streaming: failed to decode value: %w", err)
	}

	var key []byte
	if rec.Key != "" {
		key, err = base64.StdEncoding.DecodeString(rec.Key)
		if err != nil {
			return Message{}, fmt.Errorf("streaming: failed to decode key: %w", err)
		}
	}

	return Message{
		Key:       key,
		Value:     value,
		Topic:     rec.Topic,
		Partition: rec.Partition,
		Offset:    rec.Offset,
	}, nil
}

// Commit commits the offset for a consumed message.
func (c *KafkaRESTConsumer) Commit(ctx context.Context, msg Message) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errConsumerClosed
	}
	baseURI := c.baseURI
	c.mu.Unlock()

	commitBody := restCommitRequest{
		Offsets: []restCommitOffset{
			{
				Topic:     msg.Topic,
				Partition: msg.Partition,
				Offset:    msg.Offset,
			},
		},
	}

	payload, err := json.Marshal(commitBody)
	if err != nil {
		return fmt.Errorf("streaming: failed to marshal commit request: %w", err)
	}

	url := fmt.Sprintf("%s/offsets", baseURI)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("streaming: failed to create commit request: %w", err)
	}
	req.Header.Set("Content-Type", "application/vnd.kafka.v2+json")
	c.setAuth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("streaming: commit failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("streaming: commit failed: status %d, body: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// Close destroys the consumer instance on the REST Proxy.
func (c *KafkaRESTConsumer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	if c.baseURI == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURI, nil)
	if err != nil {
		return fmt.Errorf("streaming: failed to create delete request: %w", err)
	}
	req.Header.Set("Content-Type", "application/vnd.kafka.v2+json")
	c.setAuth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("streaming: consumer delete failed: %w", err)
	}
	resp.Body.Close()

	return nil
}

func (c *KafkaRESTConsumer) setAuth(req *http.Request) {
	if c.config.SASLUsername != "" && c.config.SASLPassword != "" {
		req.SetBasicAuth(c.config.SASLUsername, c.config.SASLPassword)
	}
}
