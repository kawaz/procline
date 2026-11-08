use serde::{Deserialize, Serialize};

/// Which environment variables to collect.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvPolicy {
    #[default]
    None,
    Allowlist(Vec<String>),
    All,
}

/// Decides from the variable name whether the value is redacted.
pub type IsSecretFn = dyn Fn(&str) -> bool + Send + Sync;

/// Produces the redacted value from the name and the value.
pub type RedactFn = dyn Fn(&str, &str) -> String + Send + Sync;

/// The pair of functions that redact environment values.
pub struct Redaction {
    pub is_secret: Box<IsSecretFn>,
    pub redact: Box<RedactFn>,
}

impl Default for Redaction {
    fn default() -> Self {
        Self {
            is_secret: Box::new(default_is_secret),
            redact: Box::new(default_redact),
        }
    }
}

/// Default secret-name predicate.
pub fn default_is_secret(_name: &str) -> bool {
    todo!()
}

/// Default redaction: keeps the name, hides the value.
pub fn default_redact(_name: &str, _value: &str) -> String {
    todo!()
}
