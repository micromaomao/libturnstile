//! A small hand-rolled parser for `/proc/<pid>/mountinfo`.
//!
//! Currently used only by the integration tests to introspect the live
//! mount layout (a mountinfo-based mount-tree refresh is future work, see
//! §13 in `design.fd-upgrade.md`).  Only the few fields needed are
//! extracted: the kernel mount id, the parent mount id, the source-root
//! path within the backing superblock (field 4, whose only reliable
//! signal is the `//deleted` marker of an unlinked source - it is *not*
//! the bound host path in general), and the mount point within the
//! namespace (field 5).
//!
//! mountinfo is documented in `proc(5)`.  Path-like fields are
//! octal-escaped: space, tab, newline and backslash are written as
//! `\040`, `\011`, `\012` and `\134` respectively.  The source-root
//! field of a mount whose backing dentry has been unlinked while still
//! mounted gains a trailing ` //deleted` marker.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

/// A single parsed mountinfo line, limited to the fields the sandbox
/// cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MountinfoEntry {
	/// Field 1: the kernel's unique id for this mount.
	pub mnt_id: u64,
	/// Field 2: the mount id of this mount's parent.
	pub parent_mnt_id: u64,
	/// Field 4 with any trailing `//deleted` marker removed: the location
	/// of this mount's root dentry *within its source superblock*
	/// (octal-unescaped).  Note this is **not** the bound host path in
	/// general - for a bind of a mount point (e.g. `/proc`) it is just
	/// `/`.  Used only via [`Self::deleted`] to spot an unlinked source.
	pub root: OsString,
	/// True when field 4 ended in `//deleted` - the bind source was
	/// unlinked on the host while still mounted.
	pub deleted: bool,
	/// Field 5: the mount point within the (m1) mount namespace,
	/// octal-unescaped.
	pub mount_point: OsString,
}

/// Decode the octal escapes (`\040` etc.) used by the kernel for
/// whitespace and backslashes in mountinfo path fields.
fn octal_unescape(field: &[u8]) -> OsString {
	let mut out = Vec::with_capacity(field.len());
	let mut i = 0;
	while i < field.len() {
		if field[i] == b'\\' && i + 3 < field.len() {
			let d0 = field[i + 1];
			let d1 = field[i + 2];
			let d2 = field[i + 3];
			if (b'0'..=b'7').contains(&d0)
				&& (b'0'..=b'7').contains(&d1)
				&& (b'0'..=b'7').contains(&d2)
			{
				let val = ((d0 - b'0') << 6) | ((d1 - b'0') << 3) | (d2 - b'0');
				out.push(val);
				i += 4;
				continue;
			}
		}
		out.push(field[i]);
		i += 1;
	}
	OsString::from_vec(out)
}

/// Parse the entire contents of a `mountinfo` file, skipping any line
/// that doesn't have the minimum number of fields or whose numeric
/// fields don't parse.  Returns one [`MountinfoEntry`] per valid line.
pub(crate) fn parse_mountinfo(bytes: &[u8]) -> Vec<MountinfoEntry> {
	let mut entries = Vec::new();
	for line in bytes.split(|&b| b == b'\n') {
		if line.is_empty() {
			continue;
		}
		if let Some(entry) = parse_line(line) {
			entries.push(entry);
		}
	}
	entries
}

fn parse_u64(field: &[u8]) -> Option<u64> {
	std::str::from_utf8(field).ok()?.parse().ok()
}

fn parse_line(line: &[u8]) -> Option<MountinfoEntry> {
	// Split on single spaces.  The pre-separator part of the line
	// (fields 1..=6 plus optional tagged fields) never contains an
	// unescaped space within a field, so a plain split is safe up to the
	// "-" separator.
	let mut fields = line.split(|&b| b == b' ');
	let mnt_id = parse_u64(fields.next()?)?;
	let parent_mnt_id = parse_u64(fields.next()?)?;
	let _major_minor = fields.next()?; // field 3
	let root_raw = fields.next()?; // field 4
	let mount_point_raw = fields.next()?; // field 5

	// Detect the `//deleted` marker on the source-root field.  The
	// kernel appends a literal "//deleted" to an unlinked dentry's path;
	// because the path is octal-escaped, the marker itself is never
	// escaped, so we can match on the raw bytes.
	let (root_raw, deleted) = match root_raw.strip_suffix(b"//deleted") {
		Some(stripped) => (stripped, true),
		None => (root_raw, false),
	};

	Some(MountinfoEntry {
		mnt_id,
		parent_mnt_id,
		root: octal_unescape(root_raw),
		deleted,
		mount_point: octal_unescape(mount_point_raw),
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::ffi::OsStr;
	use std::os::unix::ffi::OsStrExt;

	#[test]
	fn parses_basic_line() {
		let line =
			b"36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue";
		let e = parse_line(line).unwrap();
		assert_eq!(e.mnt_id, 36);
		assert_eq!(e.parent_mnt_id, 35);
		assert_eq!(e.root, OsStr::new("/mnt1"));
		assert_eq!(e.mount_point, OsStr::new("/mnt2"));
		assert!(!e.deleted);
	}

	#[test]
	fn parses_octal_escapes_in_paths() {
		// A mount point of "/with space/and\tab" and a source root of
		// "/src dir".
		let line = b"40 39 0:33 /src\\040dir /with\\040space/and\\011tab rw - tmpfs tmpfs rw";
		let e = parse_line(line).unwrap();
		assert_eq!(e.root, OsStr::new("/src dir"));
		assert_eq!(e.mount_point.as_bytes(), b"/with space/and\ttab");
	}

	#[test]
	fn detects_deleted_marker() {
		let line = b"50 49 0:33 /gone//deleted /mnt rw - tmpfs tmpfs rw";
		let e = parse_line(line).unwrap();
		assert!(e.deleted);
		assert_eq!(e.root, OsStr::new("/gone"));
	}

	#[test]
	fn handles_optional_tagged_fields() {
		// Two optional fields (shared:2 master:3) before the "-".
		let line = b"60 0 0:33 / / rw shared:2 master:3 - tmpfs tmpfs rw";
		let e = parse_line(line).unwrap();
		assert_eq!(e.mnt_id, 60);
		assert_eq!(e.parent_mnt_id, 0);
		assert_eq!(e.root, OsStr::new("/"));
		assert_eq!(e.mount_point, OsStr::new("/"));
	}

	#[test]
	fn parse_mountinfo_skips_blank_and_bad_lines() {
		let blob = b"36 35 98:0 /a /b rw - ext4 /dev/x rw\n\nNOT A LINE\n37 35 98:0 /c /d rw - ext4 /dev/y rw\n";
		let entries = parse_mountinfo(blob);
		assert_eq!(entries.len(), 2);
		assert_eq!(entries[0].mnt_id, 36);
		assert_eq!(entries[1].mnt_id, 37);
		assert_eq!(entries[1].mount_point, OsStr::new("/d"));
	}

	#[test]
	fn roundtrips_against_real_proc_self_mountinfo() {
		// Smoke test: the live /proc/self/mountinfo must parse without
		// dropping the root mount.
		let blob = std::fs::read("/proc/self/mountinfo").unwrap();
		let entries = parse_mountinfo(&blob);
		assert!(!entries.is_empty());
		assert!(entries.iter().any(|e| e.mount_point == OsStr::new("/")));
	}
}
