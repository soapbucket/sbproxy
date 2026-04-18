package transport

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDefaultPoolConfig(t *testing.T) {
	cfg := DefaultPoolConfig()

	assert.Equal(t, 100, cfg.MaxConnections)
	assert.Equal(t, 50, cfg.MaxIdleConns)
	assert.Equal(t, 90*time.Second, cfg.IdleTimeout)
	assert.Equal(t, time.Duration(0), cfg.MaxLifetime)
}

func TestNewTransportWithPool_Defaults(t *testing.T) {
	tr := NewTransportWithPool(PoolConfig{})

	defaults := DefaultPoolConfig()
	assert.Equal(t, defaults.MaxConnections, tr.MaxConnsPerHost)
	assert.Equal(t, defaults.MaxIdleConns, tr.MaxIdleConns)
	assert.Equal(t, defaults.MaxIdleConns, tr.MaxIdleConnsPerHost)
	assert.Equal(t, defaults.IdleTimeout, tr.IdleConnTimeout)
	assert.True(t, tr.ForceAttemptHTTP2)
}

func TestNewTransportWithPool_CustomValues(t *testing.T) {
	cfg := PoolConfig{
		MaxConnections: 200,
		MaxIdleConns:   100,
		IdleTimeout:    60 * time.Second,
	}
	tr := NewTransportWithPool(cfg)

	assert.Equal(t, 200, tr.MaxConnsPerHost)
	assert.Equal(t, 100, tr.MaxIdleConns)
	assert.Equal(t, 100, tr.MaxIdleConnsPerHost)
	assert.Equal(t, 60*time.Second, tr.IdleConnTimeout)
}

func TestNewTransportWithPool_IdleClamped(t *testing.T) {
	// MaxIdleConns should not exceed MaxConnections
	cfg := PoolConfig{
		MaxConnections: 10,
		MaxIdleConns:   50,
		IdleTimeout:    30 * time.Second,
	}
	tr := NewTransportWithPool(cfg)

	assert.Equal(t, 10, tr.MaxConnsPerHost)
	assert.Equal(t, 10, tr.MaxIdleConns, "MaxIdleConns should be clamped to MaxConnections")
	assert.Equal(t, 10, tr.MaxIdleConnsPerHost)
}

func TestNewTransportWithPool_TLSHandshakeTimeout(t *testing.T) {
	tr := NewTransportWithPool(DefaultPoolConfig())
	assert.Equal(t, 10*time.Second, tr.TLSHandshakeTimeout)
}
