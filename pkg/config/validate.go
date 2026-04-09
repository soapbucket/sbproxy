package config

import "fmt"

func (o *Origin) Validate() error {
	if o.Hostname == "" {
		return fmt.Errorf("origin hostname is required")
	}
	if len(o.Action) == 0 {
		return fmt.Errorf("origin %s: action is required", o.Hostname)
	}
	return nil
}
