//! Newtypes for provider names and model identifiers.
//!
//! Provider names and model IDs were bare `String` throughout the AI
//! config, so a typo like `openAI` was indistinguishable from a valid
//! value at the type level and surfaced only as a runtime routing miss.
//! These newtypes keep the two stringly-typed domains distinct and give
//! config compilation a single place to validate them (see
//! [`crate::AiHandlerConfig::from_config`]).
//!
//! The set of valid values stays open: the provider catalog is loaded
//! from YAML and may carry custom entries, so these are validated
//! newtypes rather than closed enums.

use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;

use serde::{Deserialize, Serialize};

macro_rules! string_newtype {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(
            Clone,
            Debug,
            Default,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            Serialize,
            Deserialize,
            schemars::JsonSchema,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// View the value as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume the newtype and return the inner `String`.
            #[must_use]
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl Deref for $name {
            type Target = str;
            fn deref(&self) -> &str {
                &self.0
            }
        }

        impl Borrow<str> for $name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.0 == *other
            }
        }

        impl PartialEq<String> for $name {
            fn eq(&self, other: &String) -> bool {
                self.0 == *other
            }
        }
    };
}

string_newtype!(
    /// A provider name as written in config (`openai`, `anthropic`, a
    /// custom catalog entry, ...). Validated against the provider
    /// catalog at config compile.
    ProviderName
);

string_newtype!(
    /// A model identifier as written in config (`gpt-4o`,
    /// `claude-3-5-sonnet`, ...). Logical model names are mapped to
    /// upstream names via `ProviderConfig::model_map`.
    ModelId
);
