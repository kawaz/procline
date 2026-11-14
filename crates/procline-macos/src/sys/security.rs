//! Security framework: the dynamic code object of a process, its validity against a requirement, and its signing information. Each call passes the raw OSStatus back; what it means is decided in `procline_core::verify`.

use std::ptr;

use core_foundation::array::CFArray;
use core_foundation::base::OSStatus;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};
use security_framework::certificate::SecCertificate;
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};
use security_framework_sys::code_signing::{SecCodeRef, SecRequirementRef};

use procline_core::AuditToken;

use super::cf;

/// `kSecCSSigningInformation` (`<Security/SecCode.h>`, `1 << 1`).
const K_SEC_CS_SIGNING_INFORMATION: u32 = 1 << 1;
/// `kSecCSRequirementInformation` (`<Security/SecCode.h>`, `1 << 2`).
const K_SEC_CS_REQUIREMENT_INFORMATION: u32 = 1 << 2;
/// `kSecCSDynamicInformation` (`<Security/SecCode.h>`, `1 << 3`): the dynamic status of the running code.
const K_SEC_CS_DYNAMIC_INFORMATION: u32 = 1 << 3;
/// `kSecCSNoNetworkAccess` (`<Security/CSCommon.h>`, `1 << 29`): no online revocation checks, so the wait does not depend on the network.
const K_SEC_CS_NO_NETWORK_ACCESS: u32 = 1 << 29;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecGuestAttributeDynamicCode: CFStringRef;
    static kSecCodeInfoIdentifier: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    static kSecCodeInfoUnique: CFStringRef;
    static kSecCodeInfoCertificates: CFStringRef;
    static kSecCodeInfoFlags: CFStringRef;
    static kSecCodeInfoStatus: CFStringRef;
    static kSecCodeInfoEntitlements: CFStringRef;
    static kSecCodeInfoEntitlementsDict: CFStringRef;
    static kSecCodeInfoPList: CFStringRef;

    /// Declared with `SecCodeRef`: the function takes a `SecCode` or a `SecStaticCode` (`<Security/SecCode.h>`).
    fn SecCodeCopySigningInformation(
        code: SecCodeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> OSStatus;
}

/// How a process is addressed.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Guest {
    Pid(i32),
    /// A socket peer, by its audit token, never by its reusable pid.
    AuditToken(AuditToken),
}

/// The code object of the running process (`SecCodeCopyGuestWithAttributes` with the kernel as host). `running_code` adds `kSecGuestAttributeDynamicCode`, so the static code is the signature the kernel keeps for the running code instead of the executable on disk.
pub(crate) fn guest(guest: Guest, running_code: bool) -> Result<SecCode, OSStatus> {
    let mut attributes = GuestAttributes::new();
    match guest {
        Guest::Pid(pid) => attributes.set_pid(pid),
        Guest::AuditToken(token) => {
            let bytes = token.0.map(u32::to_ne_bytes);
            let data = CFData::from_buffer(bytes.as_flattened());
            attributes.set_audit_token(data.as_concrete_TypeRef());
        }
    }
    if running_code {
        // SAFETY: the static is a constant string of the Security framework, initialized at load time and valid for the life of the process. The host only checks that the key is present, so the value is `true`.
        let key = unsafe { kSecGuestAttributeDynamicCode };
        attributes.set_other(key, CFBoolean::true_value().as_CFType());
    }
    SecCode::copy_guest_with_attribues(None, &attributes, Flags::empty()).map_err(|e| e.code())
}

/// A requirement compiled from the requirement language.
pub(crate) fn requirement(text: &str) -> Result<SecRequirement, OSStatus> {
    text.parse()
        .map_err(|e: security_framework::base::Error| e.code())
}

/// `SecCodeCheckValidity(code, kSecCSNoNetworkAccess, requirement)`, with no requirement for `None`.
pub(crate) fn check(code: &SecCode, requirement: Option<&SecRequirement>) -> OSStatus {
    let requirement: SecRequirementRef =
        requirement.map_or(ptr::null_mut(), |r| r.as_concrete_TypeRef());
    // SAFETY: `code` is a live SecCode, and the requirement is a live SecRequirement or NULL (`__nullable`).
    unsafe {
        security_framework_sys::code_signing::SecCodeCheckValidity(
            code.as_concrete_TypeRef(),
            K_SEC_CS_NO_NETWORK_ACCESS,
            requirement,
        )
    }
}

/// The dictionary `SecCodeCopySigningInformation` returns.
pub(crate) struct SigningInfo(CFDictionary);

/// `SecCodeCopySigningInformation(code, kSecCSSigningInformation | kSecCSRequirementInformation | kSecCSDynamicInformation)`.
pub(crate) fn signing_information(code: &SecCode) -> Result<SigningInfo, OSStatus> {
    let mut info: CFDictionaryRef = ptr::null();
    // SAFETY: `code` is a live SecCode, which the function accepts in place of a SecStaticCode, and `info` receives a retained dictionary on success.
    let status = unsafe {
        SecCodeCopySigningInformation(
            code.as_concrete_TypeRef(),
            K_SEC_CS_SIGNING_INFORMATION
                | K_SEC_CS_REQUIREMENT_INFORMATION
                | K_SEC_CS_DYNAMIC_INFORMATION,
            &mut info,
        )
    };
    if status != 0 {
        return Err(status);
    }
    if info.is_null() {
        return Err(-1);
    }
    // SAFETY: a successful call returns a dictionary under the create rule (`CF_RETURNS_RETAINED`).
    Ok(SigningInfo(unsafe {
        CFDictionary::wrap_under_create_rule(info)
    }))
}

/// The keys of the signing information dictionary this crate reads.
#[derive(Clone, Copy)]
enum InfoKey {
    Identifier,
    TeamIdentifier,
    Unique,
    Certificates,
    Flags,
    Status,
    Entitlements,
    EntitlementsDict,
    PList,
}

impl InfoKey {
    fn cf_string(self) -> CFString {
        // SAFETY: the statics are constant strings of the Security framework, initialized at load time and valid for the life of the process.
        let key = unsafe {
            match self {
                Self::Identifier => kSecCodeInfoIdentifier,
                Self::TeamIdentifier => kSecCodeInfoTeamIdentifier,
                Self::Unique => kSecCodeInfoUnique,
                Self::Certificates => kSecCodeInfoCertificates,
                Self::Flags => kSecCodeInfoFlags,
                Self::Status => kSecCodeInfoStatus,
                Self::Entitlements => kSecCodeInfoEntitlements,
                Self::EntitlementsDict => kSecCodeInfoEntitlementsDict,
                Self::PList => kSecCodeInfoPList,
            }
        };
        // SAFETY: `key` is a valid CFString (see above); the get rule retains it for the wrapper.
        unsafe { CFString::wrap_under_get_rule(key) }
    }
}

impl SigningInfo {
    fn get(&self, key: InfoKey) -> Option<CFType> {
        let key = key.cf_string();
        let value = self.0.find(key.as_concrete_TypeRef().cast())?;
        if value.is_null() {
            return None;
        }
        // SAFETY: the value comes from the dictionary, which outlives this call; the get rule retains it.
        Some(unsafe { CFType::wrap_under_get_rule(*value) })
    }

    fn string(&self, key: InfoKey) -> Option<String> {
        self.get(key)?.downcast::<CFString>().map(|s| s.to_string())
    }

    fn number(&self, key: InfoKey) -> Option<u32> {
        let n = self.get(key)?.downcast::<CFNumber>()?.to_i64()?;
        u32::try_from(n).ok()
    }

    /// `kSecCodeInfoIdentifier`.
    pub(crate) fn identifier(&self) -> Option<String> {
        self.string(InfoKey::Identifier)
    }

    /// `kSecCodeInfoTeamIdentifier`.
    pub(crate) fn team_identifier(&self) -> Option<String> {
        self.string(InfoKey::TeamIdentifier)
    }

    /// `kSecCodeInfoUnique`: the cdhash bytes.
    pub(crate) fn unique(&self) -> Option<Vec<u8>> {
        self.get(InfoKey::Unique)?
            .downcast::<CFData>()
            .map(|d| d.bytes().to_vec())
    }

    /// `kSecCodeInfoFlags`: the `SecCodeSignatureFlags` of the code directory.
    pub(crate) fn flags(&self) -> Option<u32> {
        self.number(InfoKey::Flags)
    }

    /// `kSecCodeInfoStatus`: the kernel's dynamic status word of the running code.
    pub(crate) fn status(&self) -> Option<u32> {
        self.number(InfoKey::Status)
    }

    /// `kSecCodeInfoCertificates`, leaf first: (subject summary, DER).
    pub(crate) fn certificates(&self) -> Vec<(String, Vec<u8>)> {
        let Some(array) = self
            .get(InfoKey::Certificates)
            .and_then(|v| v.downcast::<CFArray>())
        else {
            return Vec::new();
        };
        cf::array_elements(&array)
            .into_iter()
            .filter_map(|item| item.downcast::<SecCertificate>())
            .map(|cert| (cert.subject_summary(), cert.to_der()))
            .collect()
    }

    /// `kSecCodeInfoEntitlementsDict` as JSON.
    pub(crate) fn entitlements(&self) -> Option<serde_json::Map<String, serde_json::Value>> {
        let dict = self
            .get(InfoKey::EntitlementsDict)?
            .downcast::<CFDictionary>()?;
        Some(cf::dictionary_to_json(&dict))
    }

    /// `kSecCodeInfoEntitlements` (the entitlements blob) is present.
    pub(crate) fn has_entitlements_blob(&self) -> bool {
        self.get(InfoKey::Entitlements).is_some()
    }

    /// A string of the sealed Info.plist (`kSecCodeInfoPList`).
    pub(crate) fn plist_string(&self, key: &str) -> Option<String> {
        let plist = self.get(InfoKey::PList)?.downcast::<CFDictionary>()?;
        cf::dictionary_string(&plist, key)
    }
}
