// Package events implements a publish-subscribe event bus for system observability and inter-component communication.
package events

import "fmt"

// ErrBusStopped is returned when trying to publish to a stopped bus
var ErrBusStopped = fmt.Errorf("event bus has been stopped")

// ErrBufferFull is returned when the event buffer is full
var ErrBufferFull = fmt.Errorf("event buffer is full")
