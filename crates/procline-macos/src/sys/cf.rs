//! Core Foundation values to Rust values.

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, CFTypeRef, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::date::CFDate;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use serde_json::Value;

/// Seconds between the Unix epoch and the Core Foundation epoch (2001-01-01T00:00:00Z).
const CF_EPOCH_UNIX_SECS: f64 = 978_307_200.0;

/// Wraps an element pointer taken from a live CF collection.
///
/// # Safety
///
/// `ptr` is a valid CF object kept alive by its collection for as long as the result is used.
unsafe fn wrap_element(ptr: *const std::ffi::c_void) -> Option<CFType> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `ptr` is a live CF object; the get rule retains it for the returned value.
    Some(unsafe { CFType::wrap_under_get_rule(ptr as CFTypeRef) })
}

/// The elements of an array, retained.
pub(crate) fn array_elements(array: &CFArray) -> Vec<CFType> {
    array
        .get_all_values()
        .into_iter()
        // SAFETY: the pointers come from `array`, which outlives this call, and each is retained by `wrap_element`.
        .filter_map(|ptr| unsafe { wrap_element(ptr) })
        .collect()
}

/// The value of `key` in a dictionary keyed by strings.
pub(crate) fn dictionary_get(dict: &CFDictionary, key: &str) -> Option<CFType> {
    let key = CFString::new(key);
    let value = dict.find(key.as_concrete_TypeRef().cast())?;
    // SAFETY: the value pointer comes from `dict`, which outlives this call, and is retained by `wrap_element`.
    unsafe { wrap_element(*value) }
}

/// The string at `key` of a dictionary, when it is a string.
pub(crate) fn dictionary_string(dict: &CFDictionary, key: &str) -> Option<String> {
    dictionary_get(dict, key)?
        .downcast::<CFString>()
        .map(|s| s.to_string())
}

/// Converts a property-list value to JSON. Data becomes an array of byte values and a date becomes Unix seconds; other types (which a property list does not hold) become `null`.
pub(crate) fn to_json(value: &CFType) -> Value {
    if let Some(s) = value.downcast::<CFString>() {
        return Value::String(s.to_string());
    }
    if let Some(b) = value.downcast::<CFBoolean>() {
        return Value::Bool(b.into());
    }
    if let Some(n) = value.downcast::<CFNumber>() {
        if let Some(i) = n.to_i64() {
            return Value::from(i);
        }
        return n
            .to_f64()
            .and_then(serde_json::Number::from_f64)
            .map_or(Value::Null, Value::Number);
    }
    if let Some(d) = value.downcast::<CFData>() {
        return Value::Array(d.bytes().iter().map(|&b| Value::from(b)).collect());
    }
    if let Some(d) = value.downcast::<CFDate>() {
        return serde_json::Number::from_f64(d.abs_time() + CF_EPOCH_UNIX_SECS)
            .map_or(Value::Null, Value::Number);
    }
    if let Some(a) = value.downcast::<CFArray>() {
        return Value::Array(array_elements(&a).iter().map(to_json).collect());
    }
    if let Some(d) = value.downcast::<CFDictionary>() {
        return Value::Object(dictionary_to_json(&d));
    }
    Value::Null
}

/// Converts a dictionary to a JSON object; entries whose key is not a string are left out.
pub(crate) fn dictionary_to_json(dict: &CFDictionary) -> serde_json::Map<String, Value> {
    let (keys, values) = dict.get_keys_and_values();
    keys.into_iter()
        .zip(values)
        .filter_map(|(k, v)| {
            // SAFETY: the pointers come from `dict`, which outlives this call, and are retained by `wrap_element`.
            let (k, v) = unsafe { (wrap_element(k)?, wrap_element(v)?) };
            let k = k.downcast::<CFString>()?.to_string();
            Some((k, to_json(&v)))
        })
        .collect()
}
