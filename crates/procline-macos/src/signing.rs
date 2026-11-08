//! The code signature of a running process.

use procline_core::{CdHash, Certificate, CodeSigning, Signature, SignatureValidity};
use security_framework::os::macos::code_signing::SecCode;

use crate::sys::security;

/// `errSecCSUnsigned` (`<Security/CSCommon.h>`): the code object is not signed at all.
const ERR_SEC_CS_UNSIGNED: i32 = -67062;
/// `errSecCSReqFailed` (`<Security/CSCommon.h>`): the code does not satisfy the requirement.
const ERR_SEC_CS_REQ_FAILED: i32 = -67050;
/// The certificate chain ends at an Apple root: Apple's own code, the App Store, and every Apple-issued developer certificate (Developer ID, Apple Development).
const APPLE_ANCHOR_REQUIREMENT: &str = "anchor apple generic";
/// `kSecCodeSignatureAdhoc` (`<Security/CSCommon.h>`).
const SIGNATURE_ADHOC: u32 = 0x0002;
/// `kSecCodeSignatureRuntime` (`<Security/CSCommon.h>`): hardened runtime.
const SIGNATURE_RUNTIME: u32 = 0x1_0000;

/// The signature of the process `pid`, looked up by pid. `None` when the code object or its signing information cannot be obtained (the process exited, or the Security framework refused).
///
/// Notarization is not checked (`notarized` is `None`).
pub(crate) fn code_signing(pid: i32) -> Option<CodeSigning> {
    let code = security::guest_for_pid(pid).ok()?;
    let validity = match security::check_validity(&code) {
        Ok(()) => SignatureValidity::Valid,
        Err(ERR_SEC_CS_UNSIGNED) => return Some(CodeSigning::Unsigned),
        Err(status) => SignatureValidity::Invalid {
            reason: describe(status),
        },
    };
    let info = security::signing_information(&code).ok()?;
    let apple_anchored = apple_anchored(&code, &validity);
    let flags = info.flags().unwrap_or(0);
    Some(CodeSigning::Signed(Signature {
        validity,
        signing_id: info.identifier(),
        team_id: info.team_identifier(),
        bundle_id: info.plist_string("CFBundleIdentifier"),
        cdhash: info
            .unique()
            .and_then(|bytes| <[u8; 20]>::try_from(bytes.as_slice()).ok())
            .map(CdHash),
        certificates: info
            .certificates()
            .into_iter()
            .map(|(summary, der)| Certificate { summary, der })
            .collect(),
        adhoc: flags & SIGNATURE_ADHOC != 0,
        hardened_runtime: flags & SIGNATURE_RUNTIME != 0,
        platform: info.has_platform_identifier(),
        entitlements: info.entitlements(),
        notarized: None,
        apple_anchored,
    }))
}

/// Whether the signature chains to an Apple root. Evaluated only for a valid signature: an invalid one fails every requirement, which says nothing about its anchor.
fn apple_anchored(code: &SecCode, validity: &SignatureValidity) -> Option<bool> {
    if *validity != SignatureValidity::Valid {
        return None;
    }
    match security::check_requirement(code, APPLE_ANCHOR_REQUIREMENT) {
        Ok(()) => Some(true),
        Err(ERR_SEC_CS_REQ_FAILED) => Some(false),
        Err(_) => None,
    }
}

/// The Security framework's message for the status, with the status number.
fn describe(status: i32) -> String {
    match security::error_message(status) {
        Some(message) => format!("{message} (OSStatus {status})"),
        None => format!("OSStatus {status}"),
    }
}
