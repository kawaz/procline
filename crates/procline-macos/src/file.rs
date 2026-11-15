//! Reading the executable's file: its digest and the app bundle around it.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
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

/// The largest `Info.plist` that is read: 1 MiB, about 27 times the largest one observed (37,825 bytes, among the 500 apps under `/Applications`, `/System/Applications` and `/System/Library/CoreServices` of a Mac on 2026-11-15).
pub(crate) const MAX_INFO_PLIST_LEN: u64 = 1 << 20;

/// The most events of one `Info.plist` that are read: about 11 times the most observed (5,948, among the same 500 apps on 2026-11-15).
pub(crate) const MAX_INFO_PLIST_EVENTS: u64 = 1 << 16;

/// The most bytes the plist reader may read from the contents of one `Info.plist`, re-reads included: 4 times `MAX_INFO_PLIST_LEN`, where the bytes read per byte of the file were at most 2.50 (binary; median 1.05) and 1.02 (XML; median 1.00) among the same 500 apps on 2026-11-15.
pub(crate) const MAX_INFO_PLIST_READ: u64 = 4 << 20;

/// The nearest `.app` directory above `path`, read from its `Contents/Info.plist`. For display only.
///
/// Design rationale: the owner of the process decides what the `Info.plist` is (any `X.app/Contents/` it creates around an executable it starts), so the file is opened without blocking and without following a symbolic link in its last component, read only when the opened file is a regular file, and read at most `MAX_INFO_PLIST_LEN` bytes, however long the file is or grows. A binary plist may refer to one object many times, which a tree of values (`plist::Value`, or serde) expands, so a few hundred bytes can take seconds and hundreds of MB; the events are read from `plist::stream` instead, which builds no tree and walks without recursion, under a limit of `MAX_INFO_PLIST_EVENTS` events and of `MAX_INFO_PLIST_READ` bytes read (the stream reads a shared object again at each reference). `plist::stream` is behind the crate's unstable feature, so the version of `plist` is pinned to `~1.10`. Only the strings directly under the top-level dictionary are taken, and only when the whole plist is read to its end; anything else is `None`, as an unreadable file is.
pub(crate) fn bundle(path: &Path) -> Option<Bundle> {
    let app = path
        .ancestors()
        .skip(1)
        .find(|dir| dir.extension().is_some_and(|ext| ext == "app"))?;
    let contents = read_info_plist(&app.join("Contents/Info.plist"))?;
    parse_bundle(contents)
}

/// The bundle ID and version of an `Info.plist`: `CFBundleIdentifier`, and `CFBundleShortVersionString` or else `CFBundleVersion`, each when it is a string directly under the top-level dictionary. `None` unless the whole plist is well formed, with a dictionary at the top, within the limits on the events and the bytes read.
fn parse_bundle(contents: Vec<u8>) -> Option<Bundle> {
    let reader = BudgetedReader {
        inner: Cursor::new(contents),
        left: MAX_INFO_PLIST_READ,
    };
    let mut events = plist::stream::Reader::new(reader);
    let mut stack: Vec<Container> = Vec::new();
    let mut root_done = false;
    let mut top_key: Option<String> = None;
    let (mut id, mut short_version, mut version) = (None, None, None);
    let mut count = 0u64;
    for event in &mut events {
        count += 1;
        if count > MAX_INFO_PLIST_EVENTS || root_done {
            return None;
        }
        let event = event.ok()?;
        // A key of a dictionary: a string, where the dictionary expects one.
        if let Some(Container::Dict { expects_key }) = stack.last_mut()
            && *expects_key
        {
            match event {
                plist::stream::Event::String(key) => {
                    *expects_key = false;
                    if stack.len() == 1 {
                        top_key = Some(key.into_owned());
                    }
                    continue;
                }
                plist::stream::Event::EndCollection => {}
                _ => return None,
            }
        }
        // A value (or the end of a collection).
        let is_value = !matches!(event, plist::stream::Event::EndCollection);
        if is_value {
            if stack.is_empty() && !matches!(event, plist::stream::Event::StartDictionary(_)) {
                return None;
            }
            if stack.len() == 1
                && let Some(key) = top_key.take()
            {
                let string = match &event {
                    plist::stream::Event::String(value) => Some(value.to_string()),
                    _ => None,
                };
                match key.as_str() {
                    "CFBundleIdentifier" => id = string,
                    "CFBundleShortVersionString" => short_version = string,
                    "CFBundleVersion" => version = string,
                    _ => {}
                }
            }
            if let Some(Container::Dict { expects_key }) = stack.last_mut() {
                *expects_key = true;
            }
        }
        match event {
            plist::stream::Event::StartArray(_) => stack.push(Container::Array),
            plist::stream::Event::StartDictionary(_) => {
                stack.push(Container::Dict { expects_key: true });
            }
            plist::stream::Event::EndCollection => {
                stack.pop()?;
                root_done = stack.is_empty();
            }
            _ => root_done = stack.is_empty(),
        }
    }
    root_done.then(|| Bundle {
        id,
        version: short_version.or(version),
    })
}

/// A collection that the events are inside of. A dictionary alternates a key (a string) and a value.
enum Container {
    Array,
    Dict { expects_key: bool },
}

/// Reads from `inner` at most `left` bytes in all, then fails. The plist reader reads a shared object again at each reference, so this bounds its time, whatever the shape of the plist.
struct BudgetedReader {
    inner: Cursor<Vec<u8>>,
    left: u64,
}

impl Read for BudgetedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            return Err(io::Error::other(
                "the read budget of the Info.plist ran out",
            ));
        }
        let allowed = usize::try_from(self.left)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let n = self.inner.read(&mut buf[..allowed])?;
        self.left -= n as u64;
        Ok(n)
    }
}

impl Seek for BudgetedReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// The contents of the regular file at `path` when it is at most `MAX_INFO_PLIST_LEN` bytes. `O_NONBLOCK` keeps the open of a FIFO without a writer from waiting, `O_NOCTTY` keeps a terminal from becoming the controlling one, `O_NOFOLLOW` refuses a symbolic link; the type is checked on the opened descriptor, so the file cannot be swapped between the check and the read.
fn read_info_plist(path: &Path) -> Option<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut contents = Vec::new();
    file.take(MAX_INFO_PLIST_LEN + 1)
        .read_to_end(&mut contents)
        .ok()?;
    (contents.len() as u64 <= MAX_INFO_PLIST_LEN).then_some(contents)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;

    use super::{
        MAX_INFO_PLIST_EVENTS, MAX_INFO_PLIST_LEN, MAX_INFO_PLIST_READ, bundle, parse_bundle,
    };

    /// `<dir>/X.app/Contents/MacOS/x`, the executable whose bundle is read, and `<dir>/X.app/Contents/Info.plist`, where the test puts what it reads. Only the directories are created.
    fn app(dir: &tempfile::TempDir) -> (PathBuf, PathBuf) {
        let contents = dir.path().join("X.app/Contents");
        std::fs::create_dir_all(contents.join("MacOS")).unwrap();
        (contents.join("MacOS/x"), contents.join("Info.plist"))
    }

    /// An XML plist with a bundle ID and a version, padded with whitespace inside the dictionary to exactly `len` bytes.
    fn plist_of_len(len: u64) -> Vec<u8> {
        let head = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>";
        let tail = "<key>CFBundleIdentifier</key><string>com.example.x</string><key>CFBundleShortVersionString</key><string>1.2</string></dict></plist>\n";
        let pad = usize::try_from(len).unwrap() - head.len() - tail.len();
        [head.as_bytes(), &vec![b' '; pad], tail.as_bytes()].concat()
    }

    fn read_as_bundle(contents: &[u8]) -> Option<procline_core::Bundle> {
        let dir = tempfile::tempdir().unwrap();
        let (exe, plist) = app(&dir);
        std::fs::write(&plist, contents).unwrap();
        bundle(&exe)
    }

    // 上限ちょうどの大きさの Info.plist は読み、bundle ID と版 (CFBundleShortVersionString) が取れる。上限は「読む」側に含まれる境界で、実物の最大 (約 37 KB) を十分に上回る大きさまでは表示用の項目が欠けない。
    #[test]
    fn a_regular_plist_up_to_the_limit_is_read() {
        let read = read_as_bundle(&plist_of_len(MAX_INFO_PLIST_LEN)).unwrap();
        assert_eq!(read.id.as_deref(), Some("com.example.x"));
        assert_eq!(read.version.as_deref(), Some("1.2"));
    }

    // 上限を 1 バイト超える Info.plist は、中身が正しい plist でも読まずに None。Info.plist はプロセスの持ち主 (守る相手と同じ uid) が大きさを決められるので、大きさで切らないと巨大なファイルで収集がメモリを使い切る。切るのは読む量そのもの (上限 + 1 バイトまで読んで超えたら捨てる) で、開いた時点の大きさの申告だけには頼らない (読んでいる間に伸びるファイルにも効く)。
    #[test]
    fn a_plist_over_the_limit_is_not_read() {
        assert_eq!(read_as_bundle(&plist_of_len(MAX_INFO_PLIST_LEN + 1)), None);
    }

    // 書き手のいない FIFO を Info.plist に置かれても、開く所で止まらずに None を返す (普通の open は書き手が現れるまで待ち、収集が止まる)。開いた後に種類を確かめて、通常のファイルでなければ読まない。FIFO は libc::mkfifo が unsafe なので /usr/bin/mkfifo で作る。
    #[test]
    fn a_fifo_without_a_writer_is_not_waited_on() {
        let dir = tempfile::tempdir().unwrap();
        let (exe, plist) = app(&dir);
        let status = Command::new("/usr/bin/mkfifo")
            .arg(&plist)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(bundle(&exe), None);
    }

    // Info.plist がディレクトリなら None (通常のファイルだけを読む)。
    #[test]
    fn a_directory_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let (exe, plist) = app(&dir);
        std::fs::create_dir(&plist).unwrap();
        assert_eq!(bundle(&exe), None);
    }

    // Info.plist が symlink なら、指す先が正しい plist でも辿らずに None。実物の app の Info.plist は symlink ではない (/Applications、/System/Applications、/System/Library/CoreServices の 500 件すべてが通常のファイル) ので、辿らなくても表示が欠ける app は無く、辿らなければ持ち主がデバイスや他のファイルを指させて読ませることができない。
    #[test]
    fn a_symlink_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let (exe, plist) = app(&dir);
        let real = dir.path().join("real.plist");
        std::fs::write(&real, plist_of_len(1024)).unwrap();
        std::os::unix::fs::symlink(&real, &plist).unwrap();
        assert_eq!(bundle(&exe), None);
    }

    /// A binary plist (`bplist00`) of `objects`, each already encoded with 4-byte references; the first is the top. Written by hand because a writer of plists never shares an object, and the cases below need shared ones.
    fn bplist(objects: &[Vec<u8>]) -> Vec<u8> {
        let mut out = b"bplist00".to_vec();
        let mut offsets = Vec::new();
        for object in objects {
            offsets.push(u32::try_from(out.len()).unwrap());
            out.extend_from_slice(object);
        }
        let table = out.len() as u64;
        for offset in offsets {
            out.extend_from_slice(&offset.to_be_bytes());
        }
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0, 4, 4]);
        out.extend_from_slice(&(objects.len() as u64).to_be_bytes());
        out.extend_from_slice(&0u64.to_be_bytes());
        out.extend_from_slice(&table.to_be_bytes());
        out
    }

    /// The marker of an object of `kind` (the high nibble) and length `len`; a length of 15 or more follows as a 4-byte integer object.
    fn marker(kind: u8, len: usize) -> Vec<u8> {
        if len < 15 {
            vec![kind | u8::try_from(len).unwrap()]
        } else {
            let mut out = vec![kind | 0x0f, 0x12];
            out.extend_from_slice(&u32::try_from(len).unwrap().to_be_bytes());
            out
        }
    }

    fn ascii(text: &str) -> Vec<u8> {
        [marker(0x50, text.len()), text.as_bytes().to_vec()].concat()
    }

    fn array(refs: &[u32]) -> Vec<u8> {
        [
            marker(0xa0, refs.len()),
            refs.iter().flat_map(|r| r.to_be_bytes()).collect(),
        ]
        .concat()
    }

    /// A dictionary of `pairs` (key reference, value reference).
    fn dict(pairs: &[(u32, u32)]) -> Vec<u8> {
        let keys = pairs.iter().flat_map(|(k, _)| k.to_be_bytes());
        let values = pairs.iter().flat_map(|(_, v)| v.to_be_bytes());
        [marker(0xd0, pairs.len()), keys.chain(values).collect()].concat()
    }

    /// `{CFBundleIdentifier: "com.example.x", k: <chain>}` where the chain is `depth` arrays, each holding the next one twice, and the last holds `leaf` twice. Read as a tree, the leaf appears 2^depth times, though the file holds it once.
    fn shared_chain(depth: u32, leaf: Vec<u8>) -> Vec<u8> {
        let first = 4;
        let mut objects = vec![
            dict(&[(1, 2), (3, first)]),
            ascii("CFBundleIdentifier"),
            ascii("com.example.x"),
            ascii("k"),
        ];
        for level in 0..depth {
            let next = first + level + 1;
            objects.push(array(&[next, next]));
        }
        objects.push(leaf);
        bplist(&objects)
    }

    // binary 形式の正常な Info.plist も XML と同じに読める (実物の 500 件のうち 40 件は binary)。版は CFBundleShortVersionString が無ければ CFBundleVersion。
    #[test]
    fn a_binary_plist_is_read() {
        let contents = bplist(&[
            dict(&[(1, 2), (3, 4)]),
            ascii("CFBundleIdentifier"),
            ascii("com.example.x"),
            ascii("CFBundleVersion"),
            ascii("7"),
        ]);
        let read = parse_bundle(contents).unwrap();
        assert_eq!(read.id.as_deref(), Some("com.example.x"));
        assert_eq!(read.version.as_deref(), Some("7"));
    }

    // 拾うのはトップレベルの辞書の直下の key だけ。入れ子の辞書の中にある同名の key は、その app の bundle ID ではない (Info.plist の中の別の対象についての記述)。
    #[test]
    fn a_key_inside_a_nested_dictionary_is_not_taken() {
        let contents = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>Nested</key><dict><key>CFBundleIdentifier</key><string>com.example.nested</string></dict></dict></plist>\n";
        let read = parse_bundle(contents.as_bytes().to_vec()).unwrap();
        assert_eq!(read.id, None);
        assert_eq!(read.version, None);
    }

    // 同じ子を何度も参照する binary plist は、木として読むと小さなファイルが指数的に膨らむ (この深さ 22 の 500 バイトに満たないファイルで、値の木にすると数秒・数百 MB)。木を作らずに event を読み、event の数 (MAX_INFO_PLIST_EVENTS) か読み取りの量 (MAX_INFO_PLIST_READ、鎖の配列は参照のたびに読み直される) の上限を超えたら、トップレベルに正しい bundle ID があっても None (途中まで読んだ値を返すと、どこまで見たかで結果が変わる)。2 つの上限はどちらか 1 つでもこのファイルを止める。
    #[test]
    fn a_plist_shared_into_an_exponential_tree_is_not_read() {
        let contents = shared_chain(22, vec![0x10, 0]);
        assert!(contents.len() < 500);
        assert_eq!(parse_bundle(contents), None);
    }

    // event の数の上限は読み取りの量とは別に効く。1 つの整数を 2^17 回参照する配列は、読み直しが小さい (整数は 1 度読めば覚えている) まま event だけが MAX_INFO_PLIST_EVENTS を超える。
    #[test]
    fn many_small_events_past_the_event_limit_are_not_read() {
        let refs = vec![4; 1 << 17];
        let contents = bplist(&[
            dict(&[(1, 2), (3, 5)]),
            ascii("CFBundleIdentifier"),
            ascii("com.example.x"),
            ascii("k"),
            vec![0x10, 0],
            array(&refs),
        ]);
        assert!(u64::try_from(refs.len()).unwrap() > MAX_INFO_PLIST_EVENTS);
        assert_eq!(parse_bundle(contents), None);
    }

    // 共有された大きい文字列は参照のたびに読み直されるので、event の数が上限より小さくても時間がかかる (1 MiB の UTF-16 の文字列なら 16,384 event で 25 秒)。reader が読んだバイト数の合計を MAX_INFO_PLIST_READ で切り、超えたら None。ここでは 64 KiB の文字列を 1,024 回 (64 MiB) 読ませる。event は約 2,000 で event の上限には掛からない。
    #[test]
    fn a_plist_reading_past_the_read_limit_is_not_read() {
        let leaf = ascii(&"a".repeat(64 << 10));
        let contents = shared_chain(10, leaf);
        const { assert!((64u64 << 10) * 1024 > MAX_INFO_PLIST_READ) };
        assert_eq!(parse_bundle(contents), None);
    }

    // 重なり合う data: 6 バイトの data のヘッダ (0x4f 0x12 と 4 バイトの長さ) を 4,000 個並べ、各 object が「自分のヘッダの直後から offset table の直前まで」(32 KiB 余り) を中身として申告する。中身の範囲は互いに重なり、offset が別々なので共有ではなく 4,000 個の別の object になる。木を作る実装では 4,000 個が別々にコピーされる (1 MiB のファイルで 8,000 個なら約 7.5 GB)。ここでは大きさを抑え (約 190 KiB、全部読むと約 128 MB)、トップレベルに正しい bundle ID があっても None を確かめる。止めるのは読み取りの量の上限 (MAX_INFO_PLIST_READ): data は event として覚えられず参照のたびに申告された全量を読み直す一方、event は 4,000 余りで MAX_INFO_PLIST_EVENTS には掛からない。
    #[test]
    fn overlapping_data_objects_are_not_read() {
        const COUNT: usize = 4_000;
        const PAD: usize = 32 << 10;
        let refs: Vec<u32> = (5..5 + u32::try_from(COUNT).unwrap()).collect();
        let head = [
            dict(&[(1, 2), (3, 4)]),
            ascii("CFBundleIdentifier"),
            ascii("com.example.x"),
            ascii("k"),
            array(&refs),
        ];
        let head_len: usize = head.iter().map(Vec::len).sum();
        let table = 8 + head_len + 6 * COUNT + PAD;
        let mut objects = head.to_vec();
        for i in 0..COUNT {
            let after_header = 8 + head_len + 6 * i + 6;
            let mut object = vec![0x4f, 0x12];
            object.extend_from_slice(&u32::try_from(table - after_header).unwrap().to_be_bytes());
            objects.push(object);
        }
        objects.last_mut().unwrap().resize(6 + PAD, 0);
        let contents = bplist(&objects);
        assert!(contents.len() as u64 <= MAX_INFO_PLIST_LEN);
        assert!((COUNT * PAD) as u64 > MAX_INFO_PLIST_READ);
        assert!((COUNT as u64) < MAX_INFO_PLIST_EVENTS);
        assert_eq!(parse_bundle(contents), None);
    }

    // set (marker の上位 4 bit が 0xc) の要素に、中身が等しい別々の object の配列の鎖を 2 本 (深さ 28、各段が次の段を 2 回参照、最下段は同じ葉) 置いた binary plist。set に入れる時の等値比較が共有を辿り直す実装では時間が 1 段ごとに約 2 倍になるが、plist の stream reader (1.10.3、stream/binary_reader.rs の read_next) は set の marker を知らず、match の最後の腕で UnknownObjectType の解析エラーにする。set の中の鎖は 1 つも読まれず等値比較もしないので、トップレベルに正しい bundle ID があっても短い時間で None。
    #[test]
    fn a_set_of_equal_chains_is_not_read() {
        const DEPTH: u32 = 28;
        let chain_a = 5;
        let chain_b = chain_a + DEPTH;
        let leaf = chain_b + DEPTH;
        let set = [
            marker(0xc0, 2),
            [chain_a, chain_b]
                .iter()
                .flat_map(|r| r.to_be_bytes())
                .collect(),
        ]
        .concat();
        let mut objects = vec![
            dict(&[(1, 2), (3, 4)]),
            ascii("CFBundleIdentifier"),
            ascii("com.example.x"),
            ascii("k"),
            set,
        ];
        for first in [chain_a, chain_b] {
            for level in 0..DEPTH {
                let next = if level + 1 == DEPTH {
                    leaf
                } else {
                    first + level + 1
                };
                objects.push(array(&[next, next]));
            }
        }
        objects.push(vec![0x10, 0]);
        assert_eq!(parse_bundle(bplist(&objects)), None);
    }

    // 深い入れ子 (XML の <array> を 40,000 段) でも、走査は再帰しないのでスタックはあふれず、event の上限で None が返る。
    #[test]
    fn a_deeply_nested_plist_does_not_overflow() {
        let depth = 40_000;
        let contents = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.example.x</string><key>k</key>{}{}</dict></plist>\n",
            "<array>".repeat(depth),
            "</array>".repeat(depth)
        );
        assert!(contents.len() as u64 <= MAX_INFO_PLIST_LEN);
        assert_eq!(parse_bundle(contents.into_bytes()), None);
    }
}
