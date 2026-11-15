//! OS-independent types for a process and its ancestors.

#![forbid(unsafe_code)]

mod binary;
mod env;
mod pin;
mod process;
mod session;
mod signature;
mod strength;
pub mod verify;

pub use binary::{BinaryField, BinaryPin, BinaryPinError};
pub use env::{EnvPolicy, IsSecretFn, RedactFn, Redaction, default_is_secret, default_redact};
pub use pin::Pinnable;
pub use process::{
    AuditToken, Credentials, Identity, NamedId, PathMeta, ProcessChain, ProcessIdentity,
    ProcessInfo, StartTime, Truncated,
};
pub use session::SessionLevel;
pub use signature::{
    Bundle, CdHash, Certificate, CertificateKind, CodeSigning, FailureReason, Mark, Root,
    RuntimeState, Signer, VerifiedFrom, VerifiedSignature,
};
pub use strength::Strength;
