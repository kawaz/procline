//! The `os.*` vocabulary items of the ACL on macOS, observing the host through the collector crate (`procline-macos`).

#![forbid(unsafe_code)]

mod os_items;

/// The `os.*` items (`os.session`, `os.console_user`, `os.login_session`, `os.not_remote`, `os.console_active`), for the application to add with `Vocabulary::register`.
///
/// `os.session` observes the levels `boot` and `awake`; the level `unlocked` is not observed yet, so pinning it fails with `Unobservable`. `os.console_user`, `os.not_remote` and `os.console_active` are not implemented yet: observing them fails, so grants using them are undecidable and none can be made.
pub fn os_items() -> Vec<procline_acl::Item> {
    os_items::items()
}
