// lifecycle.go defines Provisioner, Validator, and Cleanup lifecycle interfaces for plugins.
package plugin

// Provisioner is implemented by modules that need setup after config loading.
type Provisioner interface {
	Provision(PluginContext) error
}

// Validator is implemented by modules that need config validation.
type Validator interface {
	Validate() error
}

// Cleanup is implemented by modules that need graceful shutdown.
type Cleanup interface {
	Cleanup() error
}
