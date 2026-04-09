package wasm

import (
	"context"
	"testing"
	"time"
)

func TestNewRuntime_Defaults(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	cfg := rt.Config()
	if cfg.MaxMemoryMB != defaultMaxMemoryMB {
		t.Errorf("expected MaxMemoryMB=%d, got %d", defaultMaxMemoryMB, cfg.MaxMemoryMB)
	}
	if cfg.MaxExecDuration != defaultMaxExecDuration {
		t.Errorf("expected MaxExecDuration=%v, got %v", defaultMaxExecDuration, cfg.MaxExecDuration)
	}
}

func TestNewRuntime_CustomConfig(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{
		MaxMemoryMB:     32,
		MaxExecDuration: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	cfg := rt.Config()
	if cfg.MaxMemoryMB != 32 {
		t.Errorf("expected MaxMemoryMB=32, got %d", cfg.MaxMemoryMB)
	}
	if cfg.MaxExecDuration != 200*time.Millisecond {
		t.Errorf("expected MaxExecDuration=200ms, got %v", cfg.MaxExecDuration)
	}
}

func TestRuntime_Close(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}

	if err := rt.Close(ctx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Engine should return error after close
	_, err = rt.Engine()
	if err == nil {
		t.Error("expected error from Engine() after Close")
	}

	// Double close should be safe
	if err := rt.Close(ctx); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
}

func TestRuntime_Engine(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	engine, err := rt.Engine()
	if err != nil {
		t.Fatalf("Engine failed: %v", err)
	}
	if engine == nil {
		t.Error("expected non-nil engine")
	}
}

func TestRuntimeConfig_ApplyDefaults(t *testing.T) {
	tests := []struct {
		name     string
		input    RuntimeConfig
		wantMem  int
		wantDur  time.Duration
	}{
		{
			name:    "zero values get defaults",
			input:   RuntimeConfig{},
			wantMem: 16,
			wantDur: 100 * time.Millisecond,
		},
		{
			name:    "negative values get defaults",
			input:   RuntimeConfig{MaxMemoryMB: -1, MaxExecDuration: -1},
			wantMem: 16,
			wantDur: 100 * time.Millisecond,
		},
		{
			name:    "positive values are preserved",
			input:   RuntimeConfig{MaxMemoryMB: 64, MaxExecDuration: 500 * time.Millisecond},
			wantMem: 64,
			wantDur: 500 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.input
			cfg.applyDefaults()
			if cfg.MaxMemoryMB != tt.wantMem {
				t.Errorf("MaxMemoryMB: got %d, want %d", cfg.MaxMemoryMB, tt.wantMem)
			}
			if cfg.MaxExecDuration != tt.wantDur {
				t.Errorf("MaxExecDuration: got %v, want %v", cfg.MaxExecDuration, tt.wantDur)
			}
		})
	}
}
