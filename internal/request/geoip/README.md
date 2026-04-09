# GeoIP Package

A Go package for IP geolocation using MMDB databases with support for caching, multiple drivers, and observability features.

## Features

- **IP Geolocation**: Look up country, continent, and ASN information for IPv4 and IPv6 addresses
- **Multiple Drivers**: Support for GeoIP database and no-op implementations
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
    
    "github.com/soapbucket/sbproxy/internal/request/geoip"
)

func main() {
    // Create settings for GeoIP database
    settings := &geoip.Settings{
        Driver: geoip.DriverGeoIP,
        Params: map[string]string{
            geoip.ParamPath: "/path/to/geoip_country.mmdb",
        },
    }
    
    // Create manager
    manager, err := geoip.NewManager(settings)
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
    Driver string            `json:"driver"`      // Driver name (geoip, noop)
    Params map[string]string `json:"params"`      // Driver-specific parameters
    
    // Observability flags
    EnableMetrics bool          `json:"enable_metrics,omitempty"`
    EnableTracing bool          `json:"enable_tracing,omitempty"`
    EnableCaching bool          `json:"enable_caching,omitempty"`
    CacheDuration time.Duration `json:"cache_duration,omitempty"`
}
```

### Driver Configuration

#### GeoIP Driver

```go
settings := &geoip.Settings{
    Driver: geoip.DriverGeoIP,
    Params: map[string]string{
        geoip.ParamPath: "/path/to/geoip_country.mmdb",
    },
}
```

#### No-op Driver

```go
settings := &geoip.Settings{
    Driver: geoip.DriverNoop,
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
    Country       string `json:"country"`
    CountryCode   string `json:"country_code"`
    Continent     string `json:"continent"`
    ContinentCode string `json:"continent_code"`
    ASN           string `json:"asn"`
    ASName        string `json:"as_name"`
    ASDomain      string `json:"as_domain"`
}
```

### Constants

```go
const (
    DriverNoop  = "noop"
    DriverGeoIP = "geoip"
    
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
settings := &geoip.Settings{
    Driver: geoip.DriverGeoIP,
    Params: map[string]string{
        geoip.ParamPath: "/path/to/geoip_country.mmdb",
    },
    EnableCaching: true,
    CacheDuration: 10 * time.Minute,
}

manager, err := geoip.NewManager(settings)
if err != nil {
    log.Fatal(err)
}
defer manager.Close()

result, err := manager.Lookup(ip)
```

### With Metrics and Tracing

```go
settings := &geoip.Settings{
    Driver: geoip.DriverGeoIP,
    Params: map[string]string{
        geoip.ParamPath: "/path/to/geoip_country.mmdb",
    },
    EnableMetrics: true,
    EnableTracing: true,
}

manager, err := geoip.NewManager(settings)
if err != nil {
    log.Fatal(err)
}
defer manager.Close()

result, err := manager.Lookup(ip)
```

### Error Handling

```go
result, err := manager.Lookup(ip)
if err != nil {
    switch err {
    case geoip.ErrUnsupportedDriver:
        log.Fatal("Unsupported driver")
    case geoip.ErrInvalidSettings:
        log.Fatal("Invalid settings")
    default:
        log.Fatal("Lookup failed:", err)
    }
}
```

### Available Drivers

```go
drivers := geoip.AvailableDrivers()
fmt.Printf("Available drivers: %v\n", drivers)
// Output: [geoip noop]
```

## Testing

Run tests with:

```bash
go test ./internal/request/geoip -v
```

### Test IPs

The test suite uses specific test IPs:
- **IPv4**: `107.210.156.163`
- **IPv6**: `2001:4860:7:30e::9b`

## Database Requirements

This package requires an MMDB-format database file (`.mmdb`). The database should contain the following fields:

- `country` - Country name
- `country_code` - ISO country code
- `continent` - Continent name
- `continent_code` - Continent code
- `asn` - Autonomous System Number
- `as_name` - AS name
- `as_domain` - AS domain

## Thread Safety

All operations are thread-safe and can be used concurrently from multiple goroutines.

## Observability

### Metrics

The package provides comprehensive Prometheus metrics when `EnableMetrics` is set to `true`:

- `sb_geoip_operations_total` - Total number of GeoIP operations
- `sb_geoip_operation_duration_seconds` - Duration of GeoIP operations
- `sb_geoip_operation_errors_total` - Total number of operation errors
- `sb_geoip_lookups_total` - Total number of IP lookups (by IP version and country)
- `sb_geoip_lookup_duration_seconds` - Duration of IP lookups

### Tracing

OpenTelemetry tracing is available when `EnableTracing` is set to `true`:

- **Spans**: `geoip.lookup` and `geoip.close` operations
- **Attributes**: IP address, IP version, country, ASN information, operation duration
- **Error tracking**: Failed operations are properly recorded with error details

### Example Metrics Query

```promql
# Lookup rate by country
rate(sb_geoip_lookups_total[5m])

# Average lookup duration
rate(sb_geoip_lookup_duration_seconds_sum[5m]) / rate(sb_geoip_lookup_duration_seconds_count[5m])

# Error rate
rate(sb_geoip_operation_errors_total[5m])
```

## Performance

- **Memory efficient**: Uses efficient MMDB database format
- **Fast lookups**: O(log n) lookup time
- **Caching support**: Optional caching layer for improved performance
- **Concurrent safe**: Multiple goroutines can safely use the same manager
- **Observability overhead**: Metrics and tracing add minimal performance impact

## License

This package is part of the SoapBucket proxy project.
