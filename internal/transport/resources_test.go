package transport

import "testing"

func TestResourceLimits_AllowsUnderLimit(t *testing.T) {
	rl := NewResourceLimits(ResourceLimitsConfig{
		MaxConnections:     10,
		MaxPendingRequests: 10,
		MaxRequests:        10,
		MaxRetries:         10,
	})

	rl.AddConnection()
	rl.AddRequest()
	rl.AddPending()
	rl.AddRetry()

	if !rl.Allow() {
		t.Fatal("expected Allow() = true when all counters are under limit")
	}
}

func TestResourceLimits_RejectsOverLimit(t *testing.T) {
	tests := []struct {
		name string
		cfg  ResourceLimitsConfig
		fill func(rl *ResourceLimits)
	}{
		{
			name: "connections",
			cfg:  ResourceLimitsConfig{MaxConnections: 2},
			fill: func(rl *ResourceLimits) {
				rl.AddConnection()
				rl.AddConnection()
			},
		},
		{
			name: "pending",
			cfg:  ResourceLimitsConfig{MaxPendingRequests: 1},
			fill: func(rl *ResourceLimits) {
				rl.AddPending()
			},
		},
		{
			name: "requests",
			cfg:  ResourceLimitsConfig{MaxRequests: 3},
			fill: func(rl *ResourceLimits) {
				rl.AddRequest()
				rl.AddRequest()
				rl.AddRequest()
			},
		},
		{
			name: "retries",
			cfg:  ResourceLimitsConfig{MaxRetries: 1},
			fill: func(rl *ResourceLimits) {
				rl.AddRetry()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := NewResourceLimits(tt.cfg)
			tt.fill(rl)
			if rl.Allow() {
				t.Fatalf("expected Allow() = false when %s at limit", tt.name)
			}
		})
	}
}

func TestResourceLimits_ZeroLimitMeansUnlimited(t *testing.T) {
	rl := NewResourceLimits(ResourceLimitsConfig{}) // all zeros

	// Add many resources - should always be allowed.
	for range 1000 {
		rl.AddConnection()
		rl.AddRequest()
		rl.AddPending()
		rl.AddRetry()
	}

	if !rl.Allow() {
		t.Fatal("expected Allow() = true when all limits are zero (unlimited)")
	}
}

func TestResourceLimits_RemoveRestoresCapacity(t *testing.T) {
	rl := NewResourceLimits(ResourceLimitsConfig{MaxConnections: 1})

	rl.AddConnection()
	if rl.Allow() {
		t.Fatal("expected Allow() = false at connection limit")
	}

	rl.RemoveConnection()
	if !rl.Allow() {
		t.Fatal("expected Allow() = true after removing connection")
	}
}
