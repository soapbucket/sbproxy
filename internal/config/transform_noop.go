// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

func init() {
	transformLoaderFns[TransformNoop] = NewNoopTransform
	transformLoaderFns[TransformNone] = NewNoopTransform
}

// NoopTransform is a variable for noop transform.
var NoopTransform TransformConfig = &noopTransform{BaseTransform: BaseTransform{TransformType: TransformNoop}}

type noopTransform struct {
	BaseTransform
}

// NewNoopTransform creates and initializes a new NoopTransform.
func NewNoopTransform([]byte) (TransformConfig, error) {
	return NoopTransform, nil
}
