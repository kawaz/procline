//! Security framework: the dynamic code object of a process, its validity, and its signing information.

use std::ptr;

use core_foundation::array::CFArray;
use core_foundation::base::OSStatus;
use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};
use security_framework::certificate::SecCertificate;
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};
use security_framework_sys::code_signing::SecCodeRef;

use super::cf;

/// `kSecCSSigningInformation` (`<Security/SecCode.h>`, `1 << 1`).
const K_SEC_CS_SIGNING_INFORMATION: u32 = 1 << 1;
/// `kSecCSRequirementInformation` (`<Security/SecCode.h>`, `1 << 2`).
const K_SEC_CS_REQUIREMENT_INFORMATION: u32 = 1 << 2;
/// `kSecCSDefaultFlags` (`<Security/CSCommon.h>`).
const K_SEC_CS_DEFAULT_FLAGS: u32 = 0;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecCodeInfoIdentifier: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    static kSecCodeInfoUnique: CFStringRef;
    static kSecCodeInfoCertificates: CFStringRef;
    static kSecCodeInfoFlags: CFStringRef;
    static kSecCodeInfoPlatformIdentifier: CFStringRef;
    static kSecCodeInfoEntitlementsDict: CFStringRef;
    static kSecCodeInfoPList: CFStringRef;

    /// Declared with `SecCodeRef`: the function takes a `SecCode` or a `SecStaticCode` (`<Security/SecCode.h>`).
    fn SecCodeCopySigningInformation(
        code: SecCodeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> OSStatus;
}

/// The code object of the running process `pid` (`SecCodeCopyGuestWithAttributes` with `kSecGuestAttributePid`, the kernel as host).
pub(crate) fn guest_for_pid(pid: i32) -> Result<SecCode, OSStatus> {
    let mut attributes = GuestAttributes::new();
    attributes.set_pid(pid);
    SecCode::copy_guest_with_attribues(None, &attributes, Flags::empty()).map_err(|e| e.code())
}

/// `SecCodeCheckValidity(code, kSecCSDefaultFlags, NULL)`: the signature is intact, without any requirement on the signer.
pub(crate) fn check_validity(code: &SecCode) -> Result<(), OSStatus> {
    // SAFETY: `code` is a live SecCode, and a NULL requirement is allowed (`__nullable`).
    let status = unsafe {
        security_framework_sys::code_signing::SecCodeCheckValidity(
            code.as_concrete_TypeRef(),
            K_SEC_CS_DEFAULT_FLAGS,
            ptr::null_mut(),
        )
    };
    if status == 0 { Ok(()) } else { Err(status) }
}

/// `SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement)` with the requirement compiled from `text`. `Err` carries the status, `errSecCSReqFailed` when the code does not satisfy the requirement.
pub(crate) fn check_requirement(code: &SecCode, text: &str) -> Result<(), OSStatus> {
    let requirement: SecRequirement = text
        .parse()
        .map_err(|e: security_framework::base::Error| e.code())?;
    code.check_validity(Flags::empty(), &requirement)
        .map_err(|e| e.code())
}

/// The message of a Security framework status code.
pub(crate) fn error_message(status: OSStatus) -> Option<String> {
    security_framework::base::Error::from_code(status).message()
}

/// The dictionary `SecCodeCopySigningInformation` returns.
pub(crate) struct SigningInfo(CFDictionary);

/// `SecCodeCopySigningInformation(code, kSecCSSigningInformation | kSecCSRequirementInformation)`.
pub(crate) fn signing_information(code: &SecCode) -> Result<SigningInfo, OSStatus> {
    let mut info: CFDictionaryRef = ptr::null();
    // SAFETY: `code` is a live SecCode, which the function accepts in place of a SecStaticCode, and `info` receives a retained dictionary on success.
    let status = unsafe {
        SecCodeCopySigningInformation(
            code.as_concrete_TypeRef(),
            K_SEC_CS_SIGNING_INFORMATION | K_SEC_CS_REQUIREMENT_INFORMATION,
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
    PlatformIdentifier,
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
                Self::PlatformIdentifier => kSecCodeInfoPlatformIdentifier,
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

    /// `kSecCodeInfoFlags`: the `SecCodeSignatureFlags`.
    pub(crate) fn flags(&self) -> Option<u32> {
        let n = self.get(InfoKey::Flags)?.downcast::<CFNumber>()?.to_i64()?;
        u32::try_from(n).ok()
    }

    /// `kSecCodeInfoPlatformIdentifier` is present: the code is a platform binary.
    pub(crate) fn has_platform_identifier(&self) -> bool {
        self.get(InfoKey::PlatformIdentifier).is_some()
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

    /// A string of the sealed Info.plist (`kSecCodeInfoPList`).
    pub(crate) fn plist_string(&self, key: &str) -> Option<String> {
        let plist = self.get(InfoKey::PList)?.downcast::<CFDictionary>()?;
        cf::dictionary_string(&plist, key)
    }
}
