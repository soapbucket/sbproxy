package wasm

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Instance wraps a WASM module instance for per-request use.
type Instance struct {
	module   WasmModule
	reqCtx   *RequestContext
	exports  ModuleExports
	hasError bool
}

// NewInstance creates a new module instance from a compiled module.
func (r *Runtime) NewInstance(ctx context.Context, compiled *CompiledModule) (*Instance, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.engine == nil {
		return nil, fmt.Errorf("wasm runtime is closed")
	}

	if compiled == nil {
		return nil, fmt.Errorf("compiled module is nil")
	}

	// Each instance gets a unique name to avoid module name collisions.
	moduleCfg := NewModuleConfig().WithName("")
	module, err := r.engine.InstantiateModule(ctx, compiled.compiled, moduleCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate module %q: %w", compiled.name, err)
	}

	return &Instance{
		module:  module,
		exports: compiled.exports,
	}, nil
}

// CallOnConfig calls sb_on_config with plugin config JSON.
func (inst *Instance) CallOnConfig(ctx context.Context, config []byte) error {
	if !inst.exports.HasOnConfig {
		return nil
	}

	fn := inst.module.ExportedFunction("sb_on_config")
	if fn == nil {
		return nil
	}

	ptr, length := WriteBytes(ctx, inst.module, config)
	if len(config) > 0 && ptr == 0 {
		inst.hasError = true
		return fmt.Errorf("failed to write config to guest memory")
	}

	_, err := fn.Call(ctx, uint64(ptr), uint64(length))
	if err != nil {
		inst.hasError = true
		return fmt.Errorf("sb_on_config failed: %w", err)
	}

	return nil
}

// CallOnRequest calls sb_on_request and returns the action.
func (inst *Instance) CallOnRequest(ctx context.Context) (PluginAction, error) {
	if !inst.exports.HasOnRequest {
		return ActionContinue, nil
	}

	fn := inst.module.ExportedFunction("sb_on_request")
	if fn == nil {
		return ActionContinue, nil
	}

	results, err := fn.Call(ctx)
	if err != nil {
		inst.hasError = true
		return ActionContinue, fmt.Errorf("sb_on_request failed: %w", err)
	}

	if len(results) == 0 {
		return ActionContinue, nil
	}

	return PluginAction(results[0]), nil
}

// CallOnResponse calls sb_on_response and returns the action.
func (inst *Instance) CallOnResponse(ctx context.Context) (PluginAction, error) {
	if !inst.exports.HasOnResponse {
		return ActionContinue, nil
	}

	fn := inst.module.ExportedFunction("sb_on_response")
	if fn == nil {
		return ActionContinue, nil
	}

	results, err := fn.Call(ctx)
	if err != nil {
		inst.hasError = true
		return ActionContinue, fmt.Errorf("sb_on_response failed: %w", err)
	}

	if len(results) == 0 {
		return ActionContinue, nil
	}

	return PluginAction(results[0]), nil
}

// SetRequestContext sets the request context for this instance.
func (inst *Instance) SetRequestContext(rc *RequestContext) {
	inst.reqCtx = rc
}

// RequestContext returns the current request context.
func (inst *Instance) RequestContext() *RequestContext {
	return inst.reqCtx
}

// HasError returns true if the instance encountered an error during execution.
func (inst *Instance) HasError() bool {
	return inst.hasError
}

// Close releases the instance resources.
func (inst *Instance) Close(ctx context.Context) error {
	if inst.module != nil {
		return inst.module.Close(ctx)
	}
	return nil
}

// InstancePool manages reusable WASM instances.
type InstancePool struct {
	runtime  *Runtime
	compiled *CompiledModule
	pool     sync.Pool
	config   []byte
	timeout  time.Duration
}

// NewInstancePool creates a pool for instances of the given compiled module.
func NewInstancePool(runtime *Runtime, compiled *CompiledModule, config []byte, timeout time.Duration) *InstancePool {
	p := &InstancePool{
		runtime:  runtime,
		compiled: compiled,
		config:   config,
		timeout:  timeout,
	}

	p.pool = sync.Pool{
		New: func() any {
			return nil // Instances are created explicitly via createInstance.
		},
	}

	return p
}

// Get returns a WASM instance from the pool or creates a new one.
func (p *InstancePool) Get(ctx context.Context) (*Instance, error) {
	// Try to reuse a pooled instance.
	if v := p.pool.Get(); v != nil {
		inst := v.(*Instance)
		return inst, nil
	}

	return p.createInstance(ctx)
}

// createInstance creates a new instance, registers host functions, and calls sb_on_config.
func (p *InstancePool) createInstance(ctx context.Context) (*Instance, error) {
	inst, err := p.runtime.NewInstance(ctx, p.compiled)
	if err != nil {
		return nil, err
	}

	// If the module has sb_on_config and we have config, call it.
	if len(p.config) > 0 {
		if err := inst.CallOnConfig(ctx, p.config); err != nil {
			inst.Close(ctx)
			return nil, fmt.Errorf("failed to configure instance: %w", err)
		}
	}

	return inst, nil
}

// Put returns an instance to the pool. Tainted instances are discarded.
func (p *InstancePool) Put(inst *Instance) {
	if inst == nil {
		return
	}

	// Discard instances that encountered errors.
	if inst.HasError() {
		inst.Close(context.Background())
		return
	}

	// Clear per-request state before returning to pool.
	inst.reqCtx = nil
	p.pool.Put(inst)
}

// Close releases all pool resources. After Close, the pool must not be used.
func (p *InstancePool) Close(ctx context.Context) error {
	// sync.Pool does not provide iteration, so we drain what we can.
	for {
		v := p.pool.Get()
		if v == nil {
			break
		}
		inst := v.(*Instance)
		inst.Close(ctx)
	}
	return nil
}

// Timeout returns the configured execution timeout.
func (p *InstancePool) Timeout() time.Duration {
	return p.timeout
}
