// context.go defines PluginContext and the Initable interface for plugin initialization.
package plugin

// PluginContext provides origin-level context to plugins during initialization.
type PluginContext struct {
	OriginID    string
	WorkspaceID string
	Hostname    string
	Version     string
	Services    ServiceProvider
}

// Initable is an optional interface for plugins that need origin context.
// If a factory-created handler implements Initable, the config loader
// calls InitPlugin() after creation with the origin's context.
type Initable interface {
	InitPlugin(PluginContext) error
}
