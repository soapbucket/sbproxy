// Package messenger provides a pluggable notification system for alerts and event delivery.
package messenger

import "time"

// Driver names
const (
	// DriverMemory is a constant for driver memory.
	DriverMemory = "memory"
	// DriverRedis is a constant for driver redis.
	DriverRedis = "redis"
	// DriverGCP is a constant for driver gcp.
	DriverGCP = "gcp"
	// DriverAWS is a constant for driver aws.
	DriverAWS = "aws"
	// DriverNoop is a constant for driver noop.
	DriverNoop = "noop"
)

// Parameter keys
const (
	// ParamDelay is a constant for param delay.
	ParamDelay = "delay"
	// ParamProjectID is a constant for param project id.
	ParamProjectID = "project_id"
	// ParamCredentials is a constant for param credentials.
	ParamCredentials = "credentials"
	// ParamRegion is a constant for param region.
	ParamRegion = "region"
)

// Default values
const (
	// DefaultMemoryDelay is the default value for memory delay.
	DefaultMemoryDelay = 5 * time.Second
	// DefaultRedisDelay is the default value for redis delay.
	DefaultRedisDelay = 100 * time.Millisecond
)
