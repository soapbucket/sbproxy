package wasm

import (
	"context"
	"testing"
	"time"
)

func TestNewInstance_ClosedRuntime(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	rt.Close(ctx)

	cm := &CompiledModule{name: "test"}
	_, err = rt.NewInstance(ctx, cm)
	if err == nil {
		t.Error("expected error from NewInstance on closed runtime")
	}
}

func TestNewInstance_NilCompiled(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	_, err = rt.NewInstance(ctx, nil)
	if err == nil {
		t.Error("expected error from NewInstance with nil compiled module")
	}
}

func TestInstance_HasError(t *testing.T) {
	inst := &Instance{}
	if inst.HasError() {
		t.Error("new instance should not have error")
	}

	inst.hasError = true
	if !inst.HasError() {
		t.Error("expected HasError to return true after setting flag")
	}
}

func TestInstance_SetRequestContext(t *testing.T) {
	inst := &Instance{}
	if inst.RequestContext() != nil {
		t.Error("expected nil initial request context")
	}

	rc := NewRequestContext()
	rc.SetRequestHeader("X-Test", "value")
	inst.SetRequestContext(rc)

	got := inst.RequestContext()
	if got == nil {
		t.Fatal("expected non-nil request context after set")
	}

	val, ok := got.GetRequestHeader("X-Test")
	if !ok || val != "value" {
		t.Errorf("expected header value %q, got %q", "value", val)
	}
}

func TestInstance_CloseNilModule(t *testing.T) {
	inst := &Instance{module: nil}
	if err := inst.Close(context.Background()); err != nil {
		t.Errorf("unexpected error closing nil module instance: %v", err)
	}
}

func TestInstance_CallOnRequest_NoExport(t *testing.T) {
	inst := &Instance{
		exports: ModuleExports{HasOnRequest: false},
	}
	action, err := inst.CallOnRequest(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if action != ActionContinue {
		t.Errorf("expected ActionContinue, got %d", action)
	}
}

func TestInstance_CallOnResponse_NoExport(t *testing.T) {
	inst := &Instance{
		exports: ModuleExports{HasOnResponse: false},
	}
	action, err := inst.CallOnResponse(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if action != ActionContinue {
		t.Errorf("expected ActionContinue, got %d", action)
	}
}

func TestInstance_CallOnConfig_NoExport(t *testing.T) {
	inst := &Instance{
		exports: ModuleExports{HasOnConfig: false},
	}
	err := inst.CallOnConfig(context.Background(), []byte(`{"key":"value"}`))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewInstancePool(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	cm := &CompiledModule{
		name: "test",
		exports: ModuleExports{
			HasOnRequest: true,
			HasMalloc:    true,
		},
	}
	config := []byte(`{"threshold":100}`)
	timeout := 50 * time.Millisecond

	pool := NewInstancePool(rt, cm, config, timeout)
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	if pool.Timeout() != timeout {
		t.Errorf("expected timeout %v, got %v", timeout, pool.Timeout())
	}
}

func TestInstancePool_PutNil(t *testing.T) {
	pool := &InstancePool{}
	// Should not panic.
	pool.Put(nil)
}

func TestInstancePool_PutTainted(t *testing.T) {
	pool := &InstancePool{}
	inst := &Instance{hasError: true}
	// Tainted instance should be discarded (Close called on nil module is safe).
	pool.Put(inst)
}

func TestInstancePool_PutAndGetClean(t *testing.T) {
	pool := &InstancePool{}

	inst := &Instance{
		exports: ModuleExports{HasOnRequest: true},
	}
	rc := NewRequestContext()
	inst.SetRequestContext(rc)

	// Verify that Put clears the request context before pooling.
	// We check the instance directly since sync.Pool does not guarantee
	// retention across GC cycles.
	if inst.RequestContext() == nil {
		t.Fatal("expected request context to be set before Put")
	}

	pool.Put(inst)

	// After Put, the instance's request context should be cleared.
	if inst.reqCtx != nil {
		t.Error("expected request context to be cleared after Put")
	}
}

func TestInstancePool_CloseEmpty(t *testing.T) {
	pool := &InstancePool{}
	if err := pool.Close(context.Background()); err != nil {
		t.Errorf("unexpected error closing empty pool: %v", err)
	}
}

func TestActionEndStream_Value(t *testing.T) {
	if ActionEndStream != 2 {
		t.Errorf("expected ActionEndStream=2, got %d", ActionEndStream)
	}
}
