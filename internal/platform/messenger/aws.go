// Package messenger provides a pluggable notification system for alerts and event delivery.
//
// The AWS SQS driver requires the enterprise build. In the core build,
// configuring driver: "aws" will return ErrNotAvailable.
package messenger

import "fmt"

// ErrAWSNotAvailable is returned when the AWS SQS messenger driver is configured
// but the enterprise dependency is not compiled in.
var ErrAWSNotAvailable = fmt.Errorf("messenger: AWS SQS driver not available in core build (requires enterprise dependency)")

func init() {
	Register(DriverAWS, func(_ Settings) (Messenger, error) {
		return nil, ErrAWSNotAvailable
	})
}
