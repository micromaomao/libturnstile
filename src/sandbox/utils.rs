use std::{
	ffi::{CStr, CString},
	io::{self, Write},
};

use log::error;

use crate::{BindMountSandboxError, utils::ENABLE_LOG_IN_FORK};

/// Split a validated absolute path into (parent, leaf).
pub(crate) fn split_parent_leaf(path: &CStr) -> (CString, &CStr) {
	let bytes = path.to_bytes_with_nul();
	let last_slash = bytes
		.iter()
		.rposition(|&b| b == b'/')
		.expect("path is absolute so should have /");
	let parent = if last_slash == 0 {
		CString::new("/").unwrap()
	} else {
		CString::new(&bytes[..last_slash]).unwrap()
	};
	let leaf = CStr::from_bytes_with_nul(&bytes[last_slash + 1..])
		.expect("original path is nul-terminated");
	(parent, leaf)
}

pub(crate) fn validate_sandbox_path(path: &CStr) -> Result<(), BindMountSandboxError> {
	let bytes = path.to_bytes();
	if !bytes.starts_with(b"/") {
		return Err(BindMountSandboxError::InvalidSandboxPath(
			"path must be absolute",
			path.to_owned(),
		));
	}
	if bytes == b"/" {
		return Ok(());
	}
	if bytes.ends_with(b"/") {
		return Err(BindMountSandboxError::InvalidSandboxPath(
			"path must not have a trailing '/'",
			path.to_owned(),
		));
	}
	for component in bytes[1..].split(|&b| b == b'/') {
		if component.is_empty() {
			return Err(BindMountSandboxError::InvalidSandboxPath(
				"path must not contain consecutive '/'",
				path.to_owned(),
			));
		}
		if component == b"." || component == b".." {
			return Err(BindMountSandboxError::InvalidSandboxPath(
				"path must not contain '.' or '..' components",
				path.to_owned(),
			));
		}
	}
	Ok(())
}

/// Generate a unique scratch directory name for parking a mount into the
/// hidden scratch tmpfs (see [`BindMountSandbox::park_to_scratch`]).
pub(crate) fn next_scratch_name() -> CString {
	use std::sync::atomic::{AtomicU64, Ordering};
	static COUNTER: AtomicU64 = AtomicU64::new(0);
	let n = COUNTER.fetch_add(1, Ordering::Relaxed);
	CString::new(format!("scratch-{n}")).expect("no NUL in generated name")
}

/// Call umount("/proc/self/fd/<fd>", MNT_DETACH) in a async-signal-safe
/// manner.
pub(crate) unsafe fn umount_detach_fd(fd: libc::c_int) -> Result<(), io::Error> {
	const PREFIX: &[u8] = b"/proc/self/fd/";
	let mut buf = [0u8; PREFIX.len() + 11];
	buf[..PREFIX.len()].copy_from_slice(PREFIX);
	if let Err(e) = write!(&mut buf[PREFIX.len()..], "{}", fd) {
		if ENABLE_LOG_IN_FORK {
			error!("Failed to format fd path for umount: {}", e);
		}
		return Err(io::Error::from_raw_os_error(libc::EINVAL));
	}
	unsafe {
		if libc::umount2(buf.as_ptr() as *const libc::c_char, libc::MNT_DETACH) != 0 {
			let errno = libc::__errno_location().read();
			if ENABLE_LOG_IN_FORK {
				error!(
					"umount2(MNT_DETACH) of unmovable child failed: errno {}",
					errno
				);
			}
			return Err(io::Error::from_raw_os_error(errno));
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_validate_sandbox_path() {
		// Valid paths
		assert!(validate_sandbox_path(c"/").is_ok());
		assert!(validate_sandbox_path(c"/a").is_ok());
		assert!(validate_sandbox_path(c"/a/b").is_ok());
		assert!(validate_sandbox_path(c"/a/b/c").is_ok());
		assert!(validate_sandbox_path(c"/usr/lib").is_ok());

		// Not absolute
		assert!(validate_sandbox_path(c"a").is_err());
		assert!(validate_sandbox_path(c"a/b").is_err());
		assert!(validate_sandbox_path(c"").is_err());

		// Trailing slash
		assert!(validate_sandbox_path(c"/a/").is_err());
		assert!(validate_sandbox_path(c"/a/b/").is_err());

		// Consecutive slashes
		assert!(validate_sandbox_path(c"//").is_err());
		assert!(validate_sandbox_path(c"//a").is_err());
		assert!(validate_sandbox_path(c"/a//b").is_err());
		assert!(validate_sandbox_path(c"/a/b//").is_err());

		// Dot components
		assert!(validate_sandbox_path(c"/.").is_err());
		assert!(validate_sandbox_path(c"/..").is_err());
		assert!(validate_sandbox_path(c"/a/..").is_err());
		assert!(validate_sandbox_path(c"/a/./b").is_err());
		assert!(validate_sandbox_path(c"/a/../b").is_err());
	}
}
