// Package crypto provides encryption and decryption utilities for securing sensitive configuration values.
package crypto

import (
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// MetricsCrypto wraps a Crypto with metrics collection
type MetricsCrypto struct {
	Crypto
	cryptoType string
}

// NewMetricsCrypto creates a new metrics crypto wrapper
func NewMetricsCrypto(crypto Crypto, cryptoType string) Crypto {
	if crypto == nil {
		return nil
	}
	return &MetricsCrypto{
		Crypto:     crypto,
		cryptoType: cryptoType,
	}
}

// Encrypt wraps the Encrypt operation with metrics
func (mc *MetricsCrypto) Encrypt(data []byte) ([]byte, error) {
	startTime := time.Now()

	result, err := mc.Crypto.Encrypt(data)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.CryptoOperationError(mc.cryptoType, "encrypt", "error")
		metric.CryptoOperation(mc.cryptoType, "encrypt", "error", duration)
		return nil, err
	}

	metric.CryptoOperation(mc.cryptoType, "encrypt", "success", duration)
	metric.CryptoDataSize(mc.cryptoType, "encrypt", int64(len(data)))
	return result, nil
}

// Decrypt wraps the Decrypt operation with metrics
func (mc *MetricsCrypto) Decrypt(data []byte) ([]byte, error) {
	startTime := time.Now()

	result, err := mc.Crypto.Decrypt(data)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.CryptoOperationError(mc.cryptoType, "decrypt", "error")
		metric.CryptoOperation(mc.cryptoType, "decrypt", "error", duration)
		return nil, err
	}

	metric.CryptoOperation(mc.cryptoType, "decrypt", "success", duration)
	metric.CryptoDataSize(mc.cryptoType, "decrypt", int64(len(result)))
	return result, nil
}

// Sign wraps the Sign operation with metrics
func (mc *MetricsCrypto) Sign(data []byte) ([]byte, error) {
	startTime := time.Now()

	result, err := mc.Crypto.Sign(data)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.CryptoOperationError(mc.cryptoType, "sign", "error")
		metric.CryptoOperation(mc.cryptoType, "sign", "error", duration)
		return nil, err
	}

	metric.CryptoOperation(mc.cryptoType, "sign", "success", duration)
	metric.CryptoDataSize(mc.cryptoType, "sign", int64(len(data)))
	return result, nil
}

// Verify wraps the Verify operation with metrics
func (mc *MetricsCrypto) Verify(data1 []byte, data2 []byte) (bool, error) {
	startTime := time.Now()

	result, err := mc.Crypto.Verify(data1, data2)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.CryptoOperationError(mc.cryptoType, "verify", "error")
		metric.CryptoOperation(mc.cryptoType, "verify", "error", duration)
		return false, err
	}

	metric.CryptoOperation(mc.cryptoType, "verify", "success", duration)
	metric.CryptoDataSize(mc.cryptoType, "verify", int64(len(data1)+len(data2)))
	return result, nil
}
