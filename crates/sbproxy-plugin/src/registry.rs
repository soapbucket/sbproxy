//! inventory-based plugin registration and discovery.
//!
//! Third-party plugins register themselves via [`inventory::submit!`] using
//! [`PluginRegistration`] entries. The proxy discovers them at link time
//! without any centralized registration code.

use anyhow::Result;

use crate::traits::{ActionHandler, AuthProvider, PolicyEnforcer, TransformHandler};
use crate::{PluginError, PluginResult};

fn unique_registration<T: 'static>(
    mut registrations: impl Iterator<Item = &'static T>,
    kind: &str,
    name: &str,
) -> Option<PluginResult<&'static T>> {
    let registration = registrations.next()?;
    if registrations.next().is_some() {
        return Some(Err(PluginError::Config(format!(
            "duplicate {kind} plugin registration: {name}"
        ))));
    }
    Some(Ok(registration))
}

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
    ///
    /// The returned value is type-erased as `Box<dyn Any + Send>`; the
    /// consumer for this [`PluginKind`] downcasts it to the concrete
    /// handler type. The factory must return `Err` when the JSON config
    /// fails to deserialize or fails the plugin's own validation; the
    /// config compiler surfaces that error to the operator at load time.
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
    ///
    /// Unlike [`PluginRegistration::factory`], this returns the concrete
    /// `Box<dyn AuthProvider>` so the compile side can build
    /// `Auth::Plugin(...)` without a downcast. The factory must return
    /// `Err` when the JSON config fails to deserialize or fails the
    /// provider's own validation.
    pub factory: fn(serde_json::Value) -> Result<Box<dyn AuthProvider>>,
}

inventory::collect!(AuthPluginRegistration);

/// Look up a strongly-typed Auth plugin by name and build it from the
/// given JSON config. On a successful build the inner result holds a
/// `Box<dyn AuthProvider>` ready to be wrapped in `Auth::Plugin(...)`.
///
/// Returns `None` when no auth plugin with `name` is registered. When a
/// plugin is found, returns `Some(result)` where the inner `result` is
/// the outcome of running the registered factory.
///
/// ## Errors
///
/// The inner `Result` is `Err` when the matched factory fails, for
/// example because `config` does not deserialize into the provider's
/// config type or fails the provider's validation. A missing
/// registration is reported as the outer `None`, not as `Err`.
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

/// Factory for a strongly typed policy plugin.
pub type PolicyPluginFactory = fn(serde_json::Value) -> PluginResult<Box<dyn PolicyEnforcer>>;

/// Strongly typed policy plugin registration.
pub struct PolicyPluginRegistration {
    /// Unique policy type name.
    pub name: &'static str,
    /// Factory that builds the policy from JSON configuration.
    pub factory: PolicyPluginFactory,
}

inventory::collect!(PolicyPluginRegistration);

/// Build a registered policy plugin from JSON configuration.
///
/// Returns `None` when no policy is registered under `name`.
///
/// ## Errors
///
/// The inner result is [`PluginError::Config`] when more than one policy is
/// registered under `name`. Otherwise it contains any error returned by the
/// unique registration's factory.
pub fn build_policy_plugin(
    name: &str,
    config: serde_json::Value,
) -> Option<PluginResult<Box<dyn PolicyEnforcer>>> {
    let registration = match unique_registration(
        inventory::iter::<PolicyPluginRegistration>().filter(|item| item.name == name),
        "policy",
        name,
    )? {
        Ok(registration) => registration,
        Err(error) => return Some(Err(error)),
    };
    Some((registration.factory)(config))
}

/// Factory for a strongly typed transform plugin.
pub type TransformPluginFactory = fn(serde_json::Value) -> PluginResult<Box<dyn TransformHandler>>;

/// Strongly typed transform plugin registration.
pub struct TransformPluginRegistration {
    /// Unique transform type name.
    pub name: &'static str,
    /// Factory that builds the transform from JSON configuration.
    pub factory: TransformPluginFactory,
}

inventory::collect!(TransformPluginRegistration);

/// Build a registered transform plugin from JSON configuration.
///
/// Returns `None` when no transform is registered under `name`.
///
/// ## Errors
///
/// The inner result is [`PluginError::Config`] when more than one transform is
/// registered under `name`. Otherwise it contains any error returned by the
/// unique registration's factory.
pub fn build_transform_plugin(
    name: &str,
    config: serde_json::Value,
) -> Option<PluginResult<Box<dyn TransformHandler>>> {
    let registration = match unique_registration(
        inventory::iter::<TransformPluginRegistration>().filter(|item| item.name == name),
        "transform",
        name,
    )? {
        Ok(registration) => registration,
        Err(error) => return Some(Err(error)),
    };
    Some((registration.factory)(config))
}

/// Factory for a strongly typed action plugin.
pub type ActionPluginFactory = fn(serde_json::Value) -> PluginResult<Box<dyn ActionHandler>>;

/// Strongly typed action plugin registration.
pub struct ActionPluginRegistration {
    /// Unique action type name.
    pub name: &'static str,
    /// Factory that builds the action from JSON configuration.
    pub factory: ActionPluginFactory,
}

inventory::collect!(ActionPluginRegistration);

/// Build a registered action plugin from JSON configuration.
///
/// Returns `None` when no action is registered under `name`.
///
/// ## Errors
///
/// The inner result is [`PluginError::Config`] when more than one action is
/// registered under `name`. Otherwise it contains any error returned by the
/// unique registration's factory.
pub fn build_action_plugin(
    name: &str,
    config: serde_json::Value,
) -> Option<PluginResult<Box<dyn ActionHandler>>> {
    let registration = match unique_registration(
        inventory::iter::<ActionPluginRegistration>().filter(|item| item.name == name),
        "action",
        name,
    )? {
        Ok(registration) => registration,
        Err(error) => return Some(Err(error)),
    };
    Some((registration.factory)(config))
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;

    use serde_json::json;

    use super::*;
    use crate::{
        ActionHandler, ActionOutcome, PluginError, PluginResult, PolicyDecision, PolicyEnforcer,
        TransformContext, TransformHandler,
    };

    struct FixturePolicy;

    impl PolicyEnforcer for FixturePolicy {
        fn policy_type(&self) -> &'static str {
            "fixture_policy"
        }

        fn enforce(
            &self,
            _req: &http::Request<bytes::Bytes>,
            _ctx: &mut dyn std::any::Any,
        ) -> Pin<Box<dyn Future<Output = PluginResult<PolicyDecision>> + Send + '_>> {
            Box::pin(async { Ok(PolicyDecision::Allow) })
        }
    }

    struct FixtureTransform;

    impl TransformHandler for FixtureTransform {
        fn transform_type(&self) -> &'static str {
            "fixture_transform"
        }

        fn apply<'a>(
            &'a self,
            _body: &'a mut bytes::BytesMut,
            _content_type: Option<&'a str>,
            _ctx: &'a TransformContext<'a>,
        ) -> Pin<Box<dyn Future<Output = PluginResult<()>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct FixtureAction;

    impl ActionHandler for FixtureAction {
        fn handler_type(&self) -> &'static str {
            "fixture_action"
        }

        fn handle(
            &self,
            _req: &mut http::Request<bytes::Bytes>,
            _ctx: &mut dyn std::any::Any,
        ) -> Pin<Box<dyn Future<Output = PluginResult<ActionOutcome>> + Send + '_>> {
            Box::pin(async { Ok(ActionOutcome::Proxy) })
        }
    }

    inventory::submit! {
        PolicyPluginRegistration {
            name: "fixture_policy",
            factory: |_config| Ok(Box::new(FixturePolicy)),
        }
    }

    inventory::submit! {
        TransformPluginRegistration {
            name: "fixture_transform",
            factory: |_config| Ok(Box::new(FixtureTransform)),
        }
    }

    inventory::submit! {
        ActionPluginRegistration {
            name: "fixture_action",
            factory: |_config| Ok(Box::new(FixtureAction)),
        }
    }

    inventory::submit! {
        PolicyPluginRegistration {
            name: "duplicate_fixture_policy",
            factory: |_config| panic!("duplicate factory must not run"),
        }
    }

    inventory::submit! {
        PolicyPluginRegistration {
            name: "duplicate_fixture_policy",
            factory: |_config| panic!("duplicate factory must not run"),
        }
    }

    inventory::submit! {
        TransformPluginRegistration {
            name: "duplicate_fixture_transform",
            factory: |_config| panic!("duplicate factory must not run"),
        }
    }

    inventory::submit! {
        TransformPluginRegistration {
            name: "duplicate_fixture_transform",
            factory: |_config| panic!("duplicate factory must not run"),
        }
    }

    inventory::submit! {
        ActionPluginRegistration {
            name: "duplicate_fixture_action",
            factory: |_config| panic!("duplicate factory must not run"),
        }
    }

    inventory::submit! {
        ActionPluginRegistration {
            name: "duplicate_fixture_action",
            factory: |_config| panic!("duplicate factory must not run"),
        }
    }

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

    #[test]
    fn typed_registries_build_each_plugin_kind() {
        let policy = build_policy_plugin("fixture_policy", json!({"type":"fixture_policy"}))
            .expect("fixture policy is registered")
            .expect("fixture policy builds");
        assert_eq!(policy.policy_type(), "fixture_policy");

        let transform =
            build_transform_plugin("fixture_transform", json!({"type":"fixture_transform"}))
                .expect("fixture transform is registered")
                .expect("fixture transform builds");
        assert_eq!(transform.transform_type(), "fixture_transform");

        let action = build_action_plugin("fixture_action", json!({"type":"fixture_action"}))
            .expect("fixture action is registered")
            .expect("fixture action builds");
        assert_eq!(action.handler_type(), "fixture_action");
    }

    fn config_message<T>(result: Option<PluginResult<T>>) -> String {
        match result.expect("duplicate name has registrations") {
            Err(PluginError::Config(message)) => message,
            Err(other) => panic!("expected config error, got {other}"),
            Ok(_) => panic!("duplicate registration unexpectedly built"),
        }
    }

    #[test]
    fn typed_registries_reject_duplicate_plugin_names() {
        assert_eq!(
            config_message(build_policy_plugin(
                "duplicate_fixture_policy",
                serde_json::Value::Null,
            )),
            "duplicate policy plugin registration: duplicate_fixture_policy"
        );
        assert_eq!(
            config_message(build_transform_plugin(
                "duplicate_fixture_transform",
                serde_json::Value::Null,
            )),
            "duplicate transform plugin registration: duplicate_fixture_transform"
        );
        assert_eq!(
            config_message(build_action_plugin(
                "duplicate_fixture_action",
                serde_json::Value::Null,
            )),
            "duplicate action plugin registration: duplicate_fixture_action"
        );
    }
}
