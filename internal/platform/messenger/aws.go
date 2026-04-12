// Package messenger provides a pluggable notification system for alerts and event delivery.
//
// The AWS SQS driver is not available in this build. Configuring driver: "aws"
// will return ErrAWSNotAvailable.
package messenger

import "fmt"

// ErrAWSNotAvailable is returned when the AWS SQS messenger driver is configured
// but has not been compiled in.
var ErrAWSNotAvailable = fmt.Errorf("messenger: AWS SQS driver not available in this build")

func init() {
	Register(DriverAWS, func(_ Settings) (Messenger, error) {
		return nil, ErrAWSNotAvailable
	})
}
