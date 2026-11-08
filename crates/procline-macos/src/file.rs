//! Reading the executable's file: its digest and the app bundle around it.

use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use procline_core::Bundle;
use sha2::{Digest, Sha256};

/// `sha256:<lowercase hex>` of the contents of the file.
pub(crate) fn sha256(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let mut out = String::from("sha256:");
    for byte in hasher.finalize() {
        let _ = write!(out, "{byte:02x}");
    }
    Ok(out)
}

/// The nearest `.app` directory above `path`, read from its `Contents/Info.plist`. For display only.
pub(crate) fn bundle(path: &Path) -> Option<Bundle> {
    let app = path
        .ancestors()
        .skip(1)
        .find(|dir| dir.extension().is_some_and(|ext| ext == "app"))?;
    let plist = plist::Value::from_file(app.join("Contents/Info.plist")).ok()?;
    let dict = plist.as_dictionary()?;
    let string = |key: &str| dict.get(key)?.as_string().map(str::to_owned);
    Some(Bundle {
        id: string("CFBundleIdentifier"),
        version: string("CFBundleShortVersionString").or_else(|| string("CFBundleVersion")),
    })
}
