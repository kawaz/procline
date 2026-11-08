//! Who can replace the executable: the owner of the file and whether the user running the process can write it or any directory on the path to it.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use procline_core::PathMeta;

use crate::sys::proc as sys;

const S_ISVTX: u32 = 0o1000;
const W: u32 = 0o2;
const X: u32 = 0o1;

/// The permission bits (`rwx` as `0o7`) that apply to a user, picked by the first class that matches: owner, then group, then other.
///
/// Approximation: `groups` is the group list of the process credential, which the kernel reports up to 16 entries (`NGROUPS`); memberships beyond that are not seen, so a file writable only through such a group is reported as not writable. The superuser is not special-cased: for uid 0 the owner bits decide like for anyone else (root is outside the threat model, which is other processes of the same uid).
fn class_bits(owner: u32, group: u32, mode: u32, uid: u32, groups: &[u32]) -> u32 {
    if owner == uid {
        (mode >> 6) & 0o7
    } else if groups.contains(&group) {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    }
}

/// The user can write the file itself.
fn can_write_file(meta: &fs::Metadata, uid: u32, groups: &[u32]) -> bool {
    class_bits(meta.uid(), meta.gid(), meta.mode(), uid, groups) & W != 0
}

/// The user can replace the entry owned by `entry_owner` in the directory: write and search permission on the directory, and, when the directory is sticky (`/tmp`), owning the directory or the entry.
fn can_replace_entry(dir: &fs::Metadata, entry_owner: u32, uid: u32, groups: &[u32]) -> bool {
    let bits = class_bits(dir.uid(), dir.gid(), dir.mode(), uid, groups);
    let writable = bits & (W | X) == (W | X);
    let sticky_allows = dir.mode() & S_ISVTX == 0 || dir.uid() == uid || entry_owner == uid;
    writable && sticky_allows
}

/// `PathMeta` of `path` for the user `uid` with the group list `groups`. `None` when the file or a directory on the path cannot be examined.
///
/// A file or directory on a read-only mount (the sealed system volume) cannot be changed by anyone, whatever its mode says, so it does not count as writable.
pub(crate) fn path_meta(path: &Path, uid: u32, groups: &[u32]) -> Option<PathMeta> {
    let file = fs::metadata(path).ok()?;
    let mut writable =
        !sys::is_on_read_only_mount(path).ok()? && can_write_file(&file, uid, groups);
    let mut entry_owner = file.uid();
    for dir in path.ancestors().skip(1) {
        if dir.as_os_str().is_empty() {
            break;
        }
        let meta = fs::metadata(dir).ok()?;
        writable |= !sys::is_on_read_only_mount(dir).ok()?
            && can_replace_entry(&meta, entry_owner, uid, groups);
        entry_owner = meta.uid();
    }
    Some(PathMeta {
        owner_uid: file.uid(),
        writable_by_user: writable,
    })
}

#[cfg(test)]
mod tests {
    use super::class_bits;

    // 権限の区分は最初に当たったものだけを見る (POSIX のファイル権限の規則)。所有者なら所有者の bit だけで、other に書き込みがあっても所有者の bit が無ければ書けない。
    #[test]
    fn owner_class_hides_group_and_other() {
        assert_eq!(class_bits(501, 20, 0o577, 501, &[20]), 0o5);
    }

    // 所有者でなく、所属グループにファイルのグループがあれば group の bit を見る (グループに書ける場所を「書けない」と誤らない)。
    #[test]
    fn group_class_applies_to_members() {
        assert_eq!(class_bits(0, 80, 0o775, 501, &[20, 80]), 0o7);
    }

    // 所有者でもグループでもなければ other の bit。
    #[test]
    fn other_class_applies_to_the_rest() {
        assert_eq!(class_bits(0, 0, 0o755, 501, &[20]), 0o5);
    }
}
