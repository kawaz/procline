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
    /// The target, by the audit token the caller passed, never by its reusable pid.
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

/// The subject summary of a certificate (`SecCertificateCopySubjectSummary`), `None` when the function returns NULL (`__nullable`; observed for a certificate with an empty subject). Not `SecCertificate::subject_summary` of security-framework, which panics on NULL.
pub(crate) fn subject_summary(certificate: &SecCertificate) -> Option<String> {
    // SAFETY: `certificate` is a live SecCertificate; the result is NULL or a string under the create rule.
    let summary = unsafe {
        security_framework_sys::certificate::SecCertificateCopySubjectSummary(
            certificate.as_concrete_TypeRef(),
        )
    };
    // SAFETY: a non-NULL result is owned by the caller (create rule).
    (!summary.is_null()).then(|| unsafe { CFString::wrap_under_create_rule(summary) }.to_string())
}

/// The dictionary `SecCodeCopySigningInformation` returns.
pub(crate) struct SigningInfo(CFDictionary);

/// `SecCodeCopySigningInformation(code, kSecCSSigningInformation | kSecCSDynamicInformation)`: every key read from the dictionary comes with these two flags; the embedded requirements are not read (the requirements are evaluated with `SecCodeCheckValidity`).
pub(crate) fn signing_information(code: &SecCode) -> Result<SigningInfo, OSStatus> {
    let mut info: CFDictionaryRef = ptr::null();
    // SAFETY: `code` is a live SecCode, which the function accepts in place of a SecStaticCode, and `info` receives a retained dictionary on success.
    let status = unsafe {
        SecCodeCopySigningInformation(
            code.as_concrete_TypeRef(),
            K_SEC_CS_SIGNING_INFORMATION | K_SEC_CS_DYNAMIC_INFORMATION,
            &mut info,
        )
    };
    // SAFETY: `info` is NULL or the dictionary the call stored, retained for the caller.
    unsafe { owned_result(status, info) }.map(SigningInfo)
}

/// Takes ownership of the dictionary a `Copy` call stored through its output pointer, whatever status it returned: a dictionary stored by a failing call is released here instead of leaked. A success without a dictionary is `Err(-1)`.
///
/// # Safety
///
/// `dictionary` is NULL or a dictionary retained for the caller (`CF_RETURNS_RETAINED`), not used after this call.
unsafe fn owned_result(
    status: OSStatus,
    dictionary: CFDictionaryRef,
) -> Result<CFDictionary, OSStatus> {
    // SAFETY: by the contract above, a non-NULL dictionary is owned by the caller, so the create rule takes that ownership.
    let owned = (!dictionary.is_null())
        .then(|| unsafe { CFDictionary::wrap_under_create_rule(dictionary) });
    match (status, owned) {
        (0, Some(dictionary)) => Ok(dictionary),
        (0, None) => Err(-1),
        (status, _) => Err(status),
    }
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

    /// `kSecCodeInfoCertificates`, leaf first: (subject summary, DER); empty without the key. `None` when the value is not an array of certificates (not an array, or an element that is NULL or not a certificate): the chain could not be read, and an empty or shorter list would not say so.
    pub(crate) fn certificates(&self) -> Option<Vec<(Option<String>, Vec<u8>)>> {
        let Some(value) = self.get(InfoKey::Certificates) else {
            return Some(Vec::new());
        };
        let array = value.downcast::<CFArray>()?;
        let elements = cf::array_elements(&array);
        if usize::try_from(array.len()).ok()? != elements.len() {
            return None;
        }
        elements
            .into_iter()
            .map(|item| {
                let certificate = item.downcast::<SecCertificate>()?;
                Some((subject_summary(&certificate), certificate.to_der()))
            })
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

#[cfg(test)]
mod tests {
    use std::ptr;

    use core_foundation::array::CFArray;
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::dictionary::{CFDictionary, CFMutableDictionary};
    use core_foundation::string::CFString;
    use security_framework::certificate::SecCertificate;

    use super::{InfoKey, SigningInfo, owned_result, subject_summary};

    /// A self-signed certificate with an empty subject and issuer (`openssl req -x509 -newkey rsa:2048 -nodes -subj "/" -outform DER`; the key was discarded).
    const EMPTY_SUBJECT: &[u8] = include_bytes!("../../tests/fixtures/empty-subject.der");

    /// Signing information holding only `kSecCodeInfoCertificates`, with the value, or nothing for `None`.
    fn with_certificates(value: Option<CFType>) -> SigningInfo {
        let pairs: Vec<(CFType, CFType)> = value
            .map(|value| (InfoKey::Certificates.cf_string().as_CFType(), value))
            .into_iter()
            .collect();
        SigningInfo(CFDictionary::from_CFType_pairs(&pairs).to_untyped())
    }

    // SecCertificateCopySubjectSummary は __nullable で、subject が空の証明書では NULL を返す (観測)。security-framework の SecCertificate::subject_summary は NULL を包もうとして panic するので使わず、自前のラッパで None にする。そういう証明書で署名したプロセスが接続しても、収集する側が落ちないため。対照として、subject のある証明書 (launchd の署名の leaf、Apple の "Software Signing") は要約を返す。
    #[test]
    fn a_certificate_with_an_empty_subject_has_no_summary() {
        let certificate = SecCertificate::from_der(EMPTY_SUBJECT).unwrap();
        assert_eq!(subject_summary(&certificate), None);

        let launchd = super::guest(super::Guest::Pid(1), false).unwrap();
        let chain = super::signing_information(&launchd)
            .unwrap()
            .certificates()
            .unwrap();
        assert_eq!(chain[0].0.as_deref(), Some("Software Signing"));
    }

    // 証明書の列 (kSecCodeInfoCertificates) を読めない時は、空や短い列を返さず None にし、署名の情報の取得の失敗 (Failed(Other)) にする。空の列は ad-hoc と読まれ、短い列は確かめていない連なりを表示に出すため。SecCode.h は「ad-hoc では無い。エラーの時は欠けるか一部だけになりうる」と書く。
    // - key が無い: 空の列 (ad-hoc の署名の形)
    // - 値が配列でない: None
    // - 配列の要素に証明書でないものがある: None
    // - 証明書の配列: 要約 (無ければ None) と DER の列
    // 該当なし: NULL を要素に持つ配列は、CF の既定の callback では作れないので試していない。要素の数を配列の長さと照らし合わせるので、NULL を飛ばした短い列も None になる。
    #[test]
    fn a_certificate_chain_that_cannot_be_read_is_none() {
        let certificate = SecCertificate::from_der(EMPTY_SUBJECT).unwrap();
        let text = CFString::new("not a certificate").as_CFType();

        assert_eq!(with_certificates(None).certificates(), Some(Vec::new()));
        assert_eq!(with_certificates(Some(text.clone())).certificates(), None);
        let mixed = CFArray::from_CFTypes(&[certificate.as_CFType(), text]);
        assert_eq!(
            with_certificates(Some(mixed.as_CFType())).certificates(),
            None
        );
        let chain = CFArray::from_CFTypes(&[certificate.as_CFType()]);
        assert_eq!(
            with_certificates(Some(chain.as_CFType())).certificates(),
            Some(vec![(None, EMPTY_SUBJECT.to_vec())])
        );
    }

    // Copy の形の呼び出し (SecCodeCopySigningInformation) が出力のポインタに辞書を入れたら、戻り値が 0 でなくても、その辞書は呼び出し側が持ち、解放する責任を負う (CF_RETURNS_RETAINED)。失敗の時に辞書を包まずに捨てると漏れる。Security framework が失敗の時に辞書を入れるかは確かめていないので、入れた場合をここで作る: 本物の辞書をもう 1 つ retain して渡し、結果を捨てた後に retain count が元の 1 に戻ることを見る (0 を返した時は成功として辞書を返し、捨てれば同じく戻る)。辞書が無い時は、失敗ならその戻り値、成功なら -1 (情報が無いのに成功とは扱わない)。
    #[test]
    fn a_dictionary_stored_by_the_call_is_released_whatever_the_status() {
        let mut dictionary = CFMutableDictionary::<CFString, CFString>::new();
        dictionary.add(&CFString::new("key"), &CFString::new("value"));
        for status in [0, -67061] {
            let handed = dictionary.clone();
            let stored = handed.as_concrete_TypeRef().cast_const();
            std::mem::forget(handed);
            assert_eq!(dictionary.retain_count(), 2);
            // SAFETY: `stored` carries the retain made by the clone above and is not used again.
            let result = unsafe { owned_result(status, stored) };
            match &result {
                Ok(_) => assert_eq!(status, 0),
                Err(returned) => assert_eq!(*returned, status),
            }
            drop(result);
            assert_eq!(dictionary.retain_count(), 1, "status {status}");
        }

        // SAFETY: NULL is allowed.
        assert_eq!(unsafe { owned_result(0, ptr::null()) }.err(), Some(-1));
        // SAFETY: NULL is allowed.
        let failed = unsafe { owned_result(-67061, ptr::null()) };
        assert_eq!(failed.err(), Some(-67061));
    }
}
