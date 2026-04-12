// Package messenger provides a pluggable notification system for alerts and event delivery.
package messenger

import "errors"

var (
	// ErrUnsupportedDriver is a sentinel error for unsupported driver conditions.
	ErrUnsupportedDriver = errors.New("messenger: unsupported driver")
	// ErrInvalidConfiguration is a sentinel error for invalid configuration conditions.
	ErrInvalidConfiguration = errors.New("messenger: invalid configuration")
	// ErrConnectionFailed is a sentinel error for connection failed conditions.
	ErrConnectionFailed = errors.New("messenger: connection failed")
	// ErrPublishFailed is a sentinel error for publish failed conditions.
	ErrPublishFailed = errors.New("messenger: publish failed")
	// ErrSubscribeFailed is a sentinel error for subscribe failed conditions.
	ErrSubscribeFailed = errors.New("messenger: subscribe failed")
	// ErrUnsubscribeFailed is a sentinel error for unsubscribe failed conditions.
	ErrUnsubscribeFailed = errors.New("messenger: unsubscribe failed")
)
