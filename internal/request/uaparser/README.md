# UAParser Library

A Go library for parsing user agent strings with support for caching, metrics, and tracing.

## Features

- **Multiple Drivers**: Support for different user agent parsing backends
- **Caching**: Built-in caching with configurable duration
- **Metrics**: Prometheus metrics integration
- **Tracing**: OpenTelemetry tracing support
- **Noop Support**: No-operation implementation for testing and fallback

## Drivers

- `uaparser`: Uses the ua-parser/uap-go library with regex file
- `noop`: No-operation implementation that returns empty results

## Usage

### Basic Usage

```go
package main

import (
    "log"
    "github.com/soapbucket/proxy/lib/uaparser"
)

func main() {
    // Create settings
    settings := &uaparser.Settings{
        Driver: uaparser.DriverUAParser,
        Params: map[string]string{
            uaparser.ParamRegexFile: "/path/to/regexes.yaml",
        },
    }

    // Create manager
    manager, err := uaparser.NewManager(settings)
    if err != nil {
        log.Fatal(err)
    }
    defer manager.Close()

    // Parse user agent
    result, err := manager.Parse("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Browser: %s %s", result.UserAgent.Family, result.UserAgent.Major)
    log.Printf("OS: %s %s", result.OS.Family, result.OS.Major)
    log.Printf("Device: %s", result.Device.Family)
}
```

### With Caching

```go
settings := &uaparser.Settings{
    Driver: uaparser.DriverUAParser,
    Params: map[string]string{
        uaparser.ParamRegexFile: "/path/to/regexes.yaml",
    },
    EnableCaching: true,
    CacheDuration: 5 * time.Minute,
}
```

### With Metrics

```go
settings := &uaparser.Settings{
    Driver: uaparser.DriverUAParser,
    Params: map[string]string{
        uaparser.ParamRegexFile: "/path/to/regexes.yaml",
    },
    EnableMetrics: true,
}
```

### With Tracing

```go
settings := &uaparser.Settings{
    Driver: uaparser.DriverUAParser,
    Params: map[string]string{
        uaparser.ParamRegexFile: "/path/to/regexes.yaml",
    },
    EnableTracing: true,
}
```

### Noop Manager

```go
settings := &uaparser.Settings{
    Driver: uaparser.DriverNoop,
}

manager, err := uaparser.NewManager(settings)
// manager will be uaparser.NoopManager
```

## Configuration

### Settings

```go
type Settings struct {
    Driver string            `json:"driver"`
    Params map[string]string `json:"params"`

    // Observability flags
    EnableMetrics bool          `json:"enable_metrics,omitempty"`
    EnableTracing bool          `json:"enable_tracing,omitempty"`
    EnableCaching bool          `json:"enable_caching,omitempty"`
    CacheDuration time.Duration `json:"cache_duration,omitempty"`
}
```

### Parameters

- `regex_file`: Path to the regexes.yaml file for the uaparser driver

## Result Structure

```go
type Result struct {
    UserAgent *uaparser.UserAgent `json:"user_agent"`
    OS        *uaparser.OS        `json:"os"`
    Device    *uaparser.Device    `json:"device"`
}
```

## Metrics

The library exposes the following Prometheus metrics:

- `sb_uaparser_operations_total`: Total number of operations
- `sb_uaparser_operation_duration_seconds`: Duration of operations
- `sb_uaparser_operation_errors_total`: Total number of operation errors
- `sb_uaparser_parses_total`: Total number of user agent parses
- `sb_uaparser_parse_duration_seconds`: Duration of user agent parses

## Tracing

The library supports OpenTelemetry tracing with the following spans:

- `uaparser.parse`: User agent parsing operation
- `uaparser.close`: Manager close operation

## Testing

Run the tests:

```bash
go test ./lib/uaparser/...
```

## Dependencies

- `github.com/ua-parser/uap-go/uaparser`: User agent parsing library
- `github.com/soapbucket/proxy/lib/cacher`: Caching library
- `github.com/soapbucket/proxy/internal/metric`: Metrics library
- `go.opentelemetry.io/otel`: OpenTelemetry tracing
