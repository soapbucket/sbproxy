# Messenger Package

This package provides a unified messaging interface for pub/sub operations across multiple backends. It supports both in-memory and distributed messaging systems with a consistent API.

## Supported Backends

- **Memory** - In-memory pub/sub for single-instance applications
- **Redis** - Distributed pub/sub using Redis
- **GCP Pub/Sub** - Google Cloud Pub/Sub for distributed messaging
- **AWS SQS** - Amazon Simple Queue Service for distributed messaging
- **Noop** - No-operation implementation for testing

## Features

- **Unified Interface**: Single API for all messaging operations
- **Context Support**: All operations support context cancellation
- **Multiple Backends**: Support for in-memory and distributed messaging
- **Thread Safe**: All implementations are safe for concurrent use
- **Flexible Configuration**: Backend-specific configuration options
- **Graceful Shutdown**: Proper cleanup of resources
- **Cloud Integration**: Native support for AWS SQS and GCP Pub/Sub
- **Production Ready**: Battle-tested implementations for production use

## Quick Start

```go
import "github.com/soapbucket/sbproxy/internal/platform/messenger"

// Create settings for memory messenger
settings := &messenger.Settings{
    Driver: "memory",
}

// Create messenger instance
msg, err := messenger.NewMessenger(settings)
if err != nil {
    log.Fatal(err)
}
defer msg.Close()

// Send a message
message := &messenger.Message{
    Body:    []byte("hello world"),
    Channel: "notifications",
    Params:  map[string]string{"user_id": "123"},
}

err = msg.Send(context.Background(), "notifications", message)
if err != nil {
    log.Fatal(err)
}

// Subscribe to messages
err = msg.Subscribe(context.Background(), "notifications", func(ctx context.Context, msg *messenger.Message) error {
    fmt.Printf("Received: %s\n", string(msg.Body))
    return nil
})
if err != nil {
    log.Fatal(err)
}
```

## Configuration

### Memory Messenger

```go
settings := &messenger.Settings{
    Driver: "memory",
}
```

### Redis Messenger

```go
settings := &messenger.Settings{
    Driver: "redis",
    Params: map[string]string{
        "dsn":      "redis://localhost:6379",
        "password": "secret",
        "db":       "0",
    },
}
```

### GCP Pub/Sub Messenger

```go
settings := &messenger.Settings{
    Driver: "gcp",
    Params: map[string]string{
        "project_id":  "my-project",
        "credentials": "/path/to/credentials.json", // Optional
    },
}
```

### AWS SQS Messenger

```go
settings := &messenger.Settings{
    Driver: "aws",
    Params: map[string]string{
        "region": "us-east-1",
        // AWS credentials are loaded from environment or IAM roles
    },
}
```

### Noop Messenger

```go
settings := &messenger.Settings{
    Driver: "noop",
}
```

## API Reference

### Core Interface

```go
type Messenger interface {
    // Send a message to a topic
    Send(ctx context.Context, topic string, message *Message) error
    
    // Subscribe to messages from a topic
    Subscribe(ctx context.Context, topic string, callback func(context.Context, *Message) error) error
    
    // Unsubscribe from a topic
    Unsubscribe(ctx context.Context, topic string) error
    
    // Close the messenger and cleanup resources
    Close() error
}
```

### Message Structure

```go
type Message struct {
    Body    []byte            `json:"body"`    // Message payload
    Params  map[string]string `json:"params"`  // Additional parameters
    Channel string            `json:"channel"` // Channel identifier
}
```

### Configuration Structure

```go
type Settings struct {
    Driver string            `json:"driver"` // Backend driver name
    Params map[string]string `json:"params"` // Backend-specific parameters
}
```

## Usage Examples

### Basic Pub/Sub

```go
// Create messenger
settings := &messenger.Settings{Driver: "memory"}
msg, err := messenger.NewMessenger(settings)
if err != nil {
    log.Fatal(err)
}
defer msg.Close()

// Publisher
go func() {
    for i := 0; i < 10; i++ {
        message := &messenger.Message{
            Body:    []byte(fmt.Sprintf("Message %d", i)),
            Channel: "events",
            Params:  map[string]string{"id": fmt.Sprintf("%d", i)},
        }
        
        err := msg.Send(context.Background(), "events", message)
        if err != nil {
            log.Printf("Failed to send message: %v", err)
        }
        
        time.Sleep(100 * time.Millisecond)
    }
}()

// Subscriber
err = msg.Subscribe(context.Background(), "events", func(ctx context.Context, m *messenger.Message) error {
    fmt.Printf("Received: %s (ID: %s)\n", string(m.Body), m.Params["id"])
    return nil
})
if err != nil {
    log.Fatal(err)
}

// Wait for messages
time.Sleep(2 * time.Second)
```

### Multiple Topics

```go
// Subscribe to multiple topics
topics := []string{"user_events", "system_events", "notifications"}

for _, topic := range topics {
    err := msg.Subscribe(context.Background(), topic, func(ctx context.Context, m *messenger.Message) error {
        fmt.Printf("[%s] %s\n", topic, string(m.Body))
        return nil
    })
    if err != nil {
        log.Printf("Failed to subscribe to %s: %v", topic, err)
    }
}

// Send to different topics
msg.Send(context.Background(), "user_events", &messenger.Message{
    Body: []byte("User logged in"),
    Channel: "user_events",
})

msg.Send(context.Background(), "system_events", &messenger.Message{
    Body: []byte("System maintenance scheduled"),
    Channel: "system_events",
})
```

### Error Handling

```go
err := msg.Subscribe(context.Background(), "events", func(ctx context.Context, m *messenger.Message) error {
    // Process message
    if err := processMessage(m); err != nil {
        // Return error to stop processing
        return fmt.Errorf("failed to process message: %w", err)
    }
    return nil
})

if err != nil {
    log.Printf("Subscription failed: %v", err)
}
```

### Context Cancellation

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

// Subscribe with timeout
err := msg.Subscribe(ctx, "events", func(ctx context.Context, m *messenger.Message) error {
    select {
    case <-ctx.Done():
        return ctx.Err()
    default:
        // Process message
        return processMessage(m)
    }
})
```

## Available Drivers

```go
drivers := messenger.AvailableDrivers()
fmt.Println("Available drivers:", drivers)
// Output: [aws gcp memory noop redis]
```

## Constants

The package provides constants for driver names and parameter keys:

```go
// Driver names
messenger.DriverMemory  // "memory"
messenger.DriverRedis   // "redis"
messenger.DriverGCP     // "gcp"
messenger.DriverAWS     // "aws"
messenger.DriverNoop    // "noop"

// Parameter keys
messenger.ParamDelay       // "delay"
messenger.ParamProjectID   // "project_id"
messenger.ParamCredentials // "credentials"
messenger.ParamRegion      // "region"

// Default values
messenger.DefaultMemoryDelay // 5 * time.Second
messenger.DefaultRedisDelay  // 100 * time.Millisecond
```

## Backend-Specific Details

### Memory Messenger

- **Use Case**: Single-instance applications, testing
- **Performance**: Very fast, no network overhead
- **Persistence**: Messages are not persisted
- **Scaling**: Limited to single process

### Redis Messenger

- **Use Case**: Distributed applications, microservices
- **Performance**: Good, depends on Redis performance
- **Persistence**: Messages can be persisted (Redis configuration)
- **Scaling**: Supports multiple instances

### GCP Pub/Sub Messenger

- **Use Case**: Distributed applications, microservices, event-driven architecture
- **Performance**: High throughput, low latency
- **Persistence**: Messages are persisted and durable
- **Scaling**: Supports multiple instances and auto-scaling
- **Features**: At-least-once delivery, ordering, dead letter topics

### AWS SQS Messenger

- **Use Case**: Distributed applications, microservices, decoupled systems
- **Performance**: High throughput, managed service
- **Persistence**: Messages are persisted and durable
- **Scaling**: Supports multiple instances and auto-scaling
- **Features**: At-least-once delivery, dead letter queues, long polling

### Noop Messenger

- **Use Case**: Testing, development
- **Performance**: Zero overhead
- **Persistence**: No messages are stored
- **Scaling**: N/A

## Testing

```go
// Use noop messenger for testing
settings := &messenger.Settings{Driver: "noop"}
msg, err := messenger.NewMessenger(settings)
if err != nil {
    t.Fatal(err)
}

// Test sending (will succeed but not actually send)
err = msg.Send(context.Background(), "test", &messenger.Message{
    Body: []byte("test message"),
})
if err != nil {
    t.Errorf("Expected no error, got %v", err)
}

// Test subscribing (will succeed but not actually subscribe)
err = msg.Subscribe(context.Background(), "test", func(ctx context.Context, m *messenger.Message) error {
    return nil
})
if err != nil {
    t.Errorf("Expected no error, got %v", err)
}
```

## Performance Considerations

- **Memory Messenger**: Fastest for single-instance applications
- **Redis Messenger**: Good for distributed applications, network latency applies
- **GCP Pub/Sub**: High performance for distributed applications, managed service
- **AWS SQS**: High performance for distributed applications, managed service
- **Noop Messenger**: Zero overhead for testing scenarios

## Error Handling

The package handles various error conditions:

- **Connection errors**: Redis connection failures
- **Context cancellation**: Operation cancellation
- **Callback errors**: Errors in message processing callbacks
- **Invalid configuration**: Unknown messenger types or invalid parameters

## Thread Safety

All messenger implementations are safe for concurrent use by multiple goroutines. The memory implementation uses `sync.Map` for thread-safe operations, while the Redis implementation relies on the Redis client's thread safety.

## Resource Management

Always call `Close()` on messenger instances to properly cleanup resources:

```go
msg, err := messenger.NewMessenger(config)
if err != nil {
    return err
}
defer msg.Close() // Ensures proper cleanup
```

## Migration Notes

If you're migrating from other messaging systems:

1. **Message Structure**: Adapt your message format to the `Message` struct
2. **Error Handling**: Update error handling to use the unified interface
3. **Configuration**: Update configuration to use `MessangerConfig`
4. **Context Support**: Add context support for cancellation and timeouts
