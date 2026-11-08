//! The thin FFI layer: every `unsafe` of the crate lives under this module, and the rest of the crate calls only the safe functions it exports.

pub(crate) mod cf;
pub(crate) mod peer;
pub(crate) mod proc;
pub(crate) mod security;
