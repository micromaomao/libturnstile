use std::ffi::CStr;

use crate::{BindMountSandboxError, sandbox::bind_mount_sandbox::BindMountSandbox};

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MountAttributes {
	pub readonly: bool,
	pub noexec: bool,
}

impl MountAttributes {
	pub fn rwx() -> Self {
		Self {
			readonly: false,
			noexec: false,
		}
	}
	pub fn rx() -> Self {
		Self {
			readonly: true,
			noexec: false,
		}
	}
	pub fn ro() -> Self {
		Self {
			readonly: true,
			noexec: true,
		}
	}
	pub fn rw() -> Self {
		Self {
			readonly: false,
			noexec: true,
		}
	}
}

impl std::fmt::Display for MountAttributes {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if self.readonly {
			write!(f, "ro")?;
		} else {
			write!(f, "rw")?;
		}
		if self.noexec {
			write!(f, ",noexec")?;
		}
		Ok(())
	}
}

#[derive(Debug)]
pub struct MountBuilder<'a, 'b> {
	pub(super) host_path: &'a CStr,
	pub(super) sandbox_path: &'a CStr,
	pub(super) attrs: MountAttributes,
	pub(super) follow_host_symlinks: bool,
	// follow_sandbox_symlinks: bool,
	pub(super) sandbox: &'b BindMountSandbox,
}

impl<'a, 'b> MountBuilder<'a, 'b> {
	pub fn attributes(&mut self, attrs: MountAttributes) -> &mut Self {
		self.attrs = attrs;
		self
	}

	/// If host path points into a location controllable or writable by
	/// the sandboxed process, this must not be used.  This only affects
	/// the path resolution for the "source" side - symlinks are still not
	/// followed when resolving the mount destination.
	pub fn follow_host_symlinks(&mut self, follow: bool) -> &mut Self {
		self.follow_host_symlinks = follow;
		self
	}

	// pub fn follow_sandbox_symlinks(&mut self, follow: bool) -> &mut Self {
	// 	self.follow_sandbox_symlinks = follow;
	// 	self
	// }

	pub fn mount(self) -> Result<(), BindMountSandboxError> {
		self.sandbox
			.mount_host_into_sandbox_impl(
				self.host_path,
				self.sandbox_path,
				self.attrs,
				self.follow_host_symlinks,
				// self.follow_sandbox_symlinks,
				false,
				true,
			)
			.map(|_| ())
	}
}
