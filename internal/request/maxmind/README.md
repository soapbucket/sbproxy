# MaxMind Package

A Go package for IP geolocation using MaxMind databases with support for caching, multiple drivers, and observability features.

## Features

- **IP Geolocation**: Look up country, continent, and ASN information for IPv4 and IPv6 addresses
- **Multiple Drivers**: Support for MaxMind database and no-op implementations
- **Caching**: Optional caching layer with configurable TTL
- **Observability**: Built-in support for Prometheus metrics and OpenTelemetry tracing
- **Thread Safe**: All operations are safe for concurrent use
- **Context Support**: All operations support context cancellation

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    "net"
    
    "github.com/soapbucket/proxy/lib/maxmind"
)

func main() {
    // Create settings for MaxMind database
    settings := &maxmind.Settings{
        Driver: maxmind.DriverMaxMind,
        Params: map[string]string{
            maxmind.ParamPath: "/path/to/ipinfo_lite.mmdb",
        },
    }
    
    // Create manager
    manager, err := maxmind.NewManager(settings)
    if err != nil {
        log.Fatal(err)
    }
    defer manager.Close()
    
    // Look up IP address
    ip := net.ParseIP("107.210.156.163")
    result, err := manager.Lookup(ip)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Country: %s (%s)\n", result.Country, result.CountryCode)
    fmt.Printf("Continent: %s (%s)\n", result.Continent, result.ContinentCode)
    fmt.Printf("ASN: %s - %s\n", result.ASN, result.ASName)
}
```

## Configuration

### Settings Structure

```go
type Settings struct {
    Driver string            `json:"driver"`      // Driver name (maxmind, noop)
    Params map[string]string `json:"params"`      // Driver-specific parameters
    
    // Observability flags
    EnableMetrics bool          `json:"enable_metrics,omitempty"`
    EnableTracing bool          `json:"enable_tracing,omitempty"`
    EnableCaching bool          `json:"enable_caching,omitempty"`
    CacheDuration time.Duration `json:"cache_duration,omitempty"`
}
```

### Driver Configuration

#### MaxMind Driver

```go
settings := &maxmind.Settings{
    Driver: maxmind.DriverMaxMind,
    Params: map[string]string{
        maxmind.ParamPath: "/path/to/ipinfo_lite.mmdb",
    },
}
```

#### No-op Driver

```go
settings := &maxmind.Settings{
    Driver: maxmind.DriverNoop,
}
```

## API Reference

### Core Interface

```go
type Manager interface {
    Lookup(net.IP) (*Result, error)
    Close() error
}
```

### Result Structure

```go
type Result struct {
    Country       string `maxminddb:"country" json:"country"`
    CountryCode   string `maxminddb:"country_code" json:"country_code"`
    Continent     string `maxminddb:"continent" json:"continent"`
    ContinentCode string `maxminddb:"continent_code" json:"continent_code"`
    ASN           string `maxminddb:"asn" json:"asn"`
    ASName        string `maxminddb:"as_name" json:"as_name"`
    ASDomain      string `maxminddb:"as_domain" json:"as_domain"`
}
```

### Constants

```go
const (
    DriverNoop    = "noop"
    DriverMaxMind = "maxmind"
    
    ParamPath = "path"
    
    DefaultCacheDuration = 5 * time.Minute
)
```

## Usage Examples

### Basic IP Lookup

```go
// IPv4 lookup
ipv4 := net.ParseIP("107.210.156.163")
result, err := manager.Lookup(ipv4)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("IPv4 Result: %+v\n", result)

// IPv6 lookup
ipv6 := net.ParseIP("2001:4860:7:30e::9b")
result, err := manager.Lookup(ipv6)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("IPv6 Result: %+v\n", result)
```

### With Caching

```go
// Create settings with caching enabled
settings := &maxmind.Settings{
    Driver: maxmind.DriverMaxMind,
    Params: map[string]string{
        maxmind.ParamPath: "/path/to/ipinfo_lite.mmdb",
    },
    EnableCaching: true,
    CacheDuration: 10 * time.Minute,
}

// Create manager (caching will be handled automatically)
manager, err := maxmind.NewManager(settings)
if err != nil {
    log.Fatal(err)
}
defer manager.Close()

// Lookups will be cached for the specified duration
result, err := manager.Lookup(ip)
```

### With Metrics and Tracing

```go
// Create settings with observability enabled
settings := &maxmind.Settings{
    Driver: maxmind.DriverMaxMind,
    Params: map[string]string{
        maxmind.ParamPath: "/path/to/ipinfo_lite.mmdb",
    },
    EnableMetrics: true,  // Enable Prometheus metrics
    EnableTracing: true,  // Enable OpenTelemetry tracing
}

// Create manager (wrappers will be applied automatically)
manager, err := maxmind.NewManager(settings)
if err != nil {
    log.Fatal(err)
}
defer manager.Close()

// Operations will be automatically instrumented
result, err := manager.Lookup(ip)
```

### Error Handling

```go
result, err := manager.Lookup(ip)
if err != nil {
    switch err {
    case maxmind.ErrUnsupportedDriver:
        log.Fatal("Unsupported driver")
    case maxmind.ErrInvalidSettings:
        log.Fatal("Invalid settings")
    default:
        log.Fatal("Lookup failed:", err)
    }
}
```

### Available Drivers

```go
drivers := maxmind.AvailableDrivers()
fmt.Printf("Available drivers: %v\n", drivers)
// Output: [maxmind noop]
```

## Testing

The package includes comprehensive tests covering:

- IP lookup functionality for both IPv4 and IPv6
- Driver registration and management
- Error handling scenarios
- Caching functionality
- No-op manager behavior

Run tests with:

```bash
go test ./lib/maxmind -v
```

### Test IPs

The test suite uses specific test IPs:
- **IPv4**: `107.210.156.163` (AT&T Enterprises)
- **IPv6**: `2001:4860:7:30e::9b` (Google LLC)

## Database Requirements

This package requires a MaxMind database file (`.mmdb` format). The database should contain the following fields:

- `country` - Country name
- `country_code` - ISO country code
- `continent` - Continent name
- `continent_code` - Continent code
- `asn` - Autonomous System Number
- `as_name` - AS name
- `as_domain` - AS domain

## Dependencies

- `github.com/oschwald/maxminddb-golang` - MaxMind database reader
- `github.com/soapbucket/proxy/lib/cacher` - Caching layer (optional)

## Thread Safety

All operations are thread-safe and can be used concurrently from multiple goroutines.

## Context Support

All operations support context cancellation for timeout handling:

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

// The manager will respect context timeouts
result, err := manager.Lookup(ip)
```

## Logging

The package uses structured logging with `log/slog`. All operations are logged with appropriate log levels:

- `DEBUG` - Normal operations
- `ERROR` - Failed operations

## Observability

### Metrics

The package provides comprehensive Prometheus metrics when `EnableMetrics` is set to `true`:

- `sb_maxmind_operations_total` - Total number of MaxMind operations
- `sb_maxmind_operation_duration_seconds` - Duration of MaxMind operations
- `sb_maxmind_operation_errors_total` - Total number of operation errors
- `sb_maxmind_lookups_total` - Total number of IP lookups (by IP version and country)
- `sb_maxmind_lookup_duration_seconds` - Duration of IP lookups

### Tracing

OpenTelemetry tracing is available when `EnableTracing` is set to `true`:

- **Spans**: `maxmind.lookup` and `maxmind.close` operations
- **Attributes**: IP address, IP version, country, ASN information, operation duration
- **Error tracking**: Failed operations are properly recorded with error details

### Example Metrics Query

```promql
# Lookup rate by country
rate(sb_maxmind_lookups_total[5m])

# Average lookup duration
rate(sb_maxmind_lookup_duration_seconds_sum[5m]) / rate(sb_maxmind_lookup_duration_seconds_count[5m])

# Error rate
rate(sb_maxmind_operation_errors_total[5m])
```

## Performance

- **Memory efficient**: Uses MaxMind's efficient database format
- **Fast lookups**: O(log n) lookup time
- **Caching support**: Optional caching layer for improved performance
- **Concurrent safe**: Multiple goroutines can safely use the same manager
- **Observability overhead**: Metrics and tracing add minimal performance impact

## License

This package is part of the SoapBucket proxy project.
