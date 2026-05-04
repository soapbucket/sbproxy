//! inventory-based plugin registration and discovery.
//!
//! Third-party plugins register themselves via [`inventory::submit!`] using
//! [`PluginRegistration`] entries. The proxy discovers them at link time
//! without any centralized registration code.

use anyhow::Result;

use crate::traits::AuthProvider;

/// Which kind of plugin this registration covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginKind {
    /// Action handler (request routing / response generation).
    Action,
    /// Authentication provider.
    Auth,
    /// Policy enforcer (rate limiting, geo-blocking, etc.).
    Policy,
    /// Body transform handler.
    Transform,
    /// Request enricher (GeoIP, UA parsing, etc.).
    Enricher,
}

/// Plugin registration entry collected by inventory at link time.
///
/// Each third-party plugin crate submits one of these per plugin type
/// it provides:
///
/// ```ignore
/// inventory::submit! {
///     PluginRegistration {
///         kind: PluginKind::Action,
///         name: "my-custom-action",
///         factory: |config| {
///             let handler = MyCustomAction::from_config(config)?;
///             Ok(Box::new(handler))
///         },
///     }
/// }
/// ```
pub struct PluginRegistration {
    /// The kind of plugin being registered.
    pub kind: PluginKind,
    /// Unique name for this plugin (e.g. "my-custom-action").
    pub name: &'static str,
    /// Factory function that creates an instance from JSON config.
    pub factory: fn(serde_json::Value) -> Result<Box<dyn std::any::Any + Send>>,
}

inventory::collect!(PluginRegistration);

/// Look up a plugin factory by kind and name.
///
/// Returns `None` if no plugin with the given kind and name is registered.
pub fn get_plugin(kind: PluginKind, name: &str) -> Option<&'static PluginRegistration> {
    inventory::iter::<PluginRegistration>().find(|r| r.kind == kind && r.name == name)
}

/// List all registered plugin names of a given kind.
pub fn list_plugins(kind: PluginKind) -> Vec<&'static str> {
    inventory::iter::<PluginRegistration>()
        .filter(|r| r.kind == kind)
        .map(|r| r.name)
        .collect()
}

/// Strongly-typed Auth plugin registration.
///
/// The base [`PluginRegistration`] uses `Box<dyn Any + Send>` for its
/// factory return type, which works for action / policy / transform /
/// enricher plugins (each consumed by a downcaster that knows the
/// concrete type) but is awkward for auth: `compile_auth` cannot know
/// every concrete auth type at build time.
///
/// This sibling channel returns `Box<dyn AuthProvider>` directly so
/// the compile side can build `Auth::Plugin(...)` without any
/// downcasts. Auth providers register here in addition to the
/// fan-out [`PluginRegistration`] (used for diagnostics / listing).
///
/// ```ignore
/// inventory::submit! {
///     AuthPluginRegistration {
///         name: "saml",
///         factory: |config| {
///             let cfg: SamlConfig = serde_json::from_value(config)?;
///             Ok(Box::new(SamlProvider { config: cfg }))
///         },
///     }
/// }
/// ```
pub struct AuthPluginRegistration {
    /// Unique name for this auth provider (e.g. `"saml"`).
    pub name: &'static str,
    /// Factory that builds a boxed AuthProvider from JSON config.
    pub factory: fn(serde_json::Value) -> Result<Box<dyn AuthProvider>>,
}

inventory::collect!(AuthPluginRegistration);

/// Look up a strongly-typed Auth plugin by name. Returns the concrete
/// `Box<dyn AuthProvider>` ready to be wrapped in `Auth::Plugin(...)`.
pub fn build_auth_plugin(
    name: &str,
    config: serde_json::Value,
) -> Option<Result<Box<dyn AuthProvider>>> {
    let reg = inventory::iter::<AuthPluginRegistration>().find(|r| r.name == name)?;
    Some((reg.factory)(config))
}

/// List all registered Auth plugin names from the typed channel.
pub fn list_auth_plugins() -> Vec<&'static str> {
    inventory::iter::<AuthPluginRegistration>()
        .map(|r| r.name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Test plugin registrations ---

    inventory::submit! {
        PluginRegistration {
            kind: PluginKind::Action,
            name: "test-action",
            factory: |_config| Ok(Box::new(42_u32)),
        }
    }

    inventory::submit! {
        PluginRegistration {
            kind: PluginKind::Auth,
            name: "test-auth",
            factory: |_config| Ok(Box::new("auth-instance")),
        }
    }

    inventory::submit! {
        PluginRegistration {
            kind: PluginKind::Action,
            name: "another-action",
            factory: |_config| Ok(Box::new(99_u32)),
        }
    }

    #[test]
    fn get_plugin_finds_registered() {
        let reg = get_plugin(PluginKind::Action, "test-action");
        assert!(reg.is_some());
        let reg = reg.unwrap();
        assert_eq!(reg.name, "test-action");
        assert_eq!(reg.kind, PluginKind::Action);
    }

    #[test]
    fn get_plugin_returns_none_for_unknown_name() {
        assert!(get_plugin(PluginKind::Action, "nonexistent").is_none());
    }

    #[test]
    fn get_plugin_returns_none_for_wrong_kind() {
        // "test-action" is registered as Action, not Auth.
        assert!(get_plugin(PluginKind::Auth, "test-action").is_none());
    }

    #[test]
    fn list_plugins_returns_all_of_kind() {
        let actions = list_plugins(PluginKind::Action);
        assert!(actions.contains(&"test-action"));
        assert!(actions.contains(&"another-action"));
        assert!(!actions.contains(&"test-auth"));
    }

    #[test]
    fn list_plugins_empty_for_unused_kind() {
        let enrichers = list_plugins(PluginKind::Enricher);
        // No enrichers registered in this test module.
        assert!(enrichers.is_empty());
    }

    #[test]
    fn factory_produces_value() {
        let reg = get_plugin(PluginKind::Action, "test-action").unwrap();
        let result = (reg.factory)(serde_json::Value::Null);
        assert!(result.is_ok());
        let boxed = result.unwrap();
        let value = boxed.downcast_ref::<u32>().unwrap();
        assert_eq!(*value, 42);
    }
}
