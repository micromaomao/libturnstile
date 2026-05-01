use std::ffi::{CStr, CString};

use crate::BindMountSandboxError;

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
