mod bind_mount_sandbox;
mod managed_bind_mount_sandbox;
mod mount_attributes;
mod mount_obj;
#[cfg(test)]
mod mountinfo;
mod namespace;
mod placeholders;
mod upgrade;
mod utils;

/// Options for [`BindMountSandbox::new`] and [`ManagedBindMountSandbox::new`].
#[derive(Debug, Clone)]
pub struct SandboxOptions {
	/// Block further user namespaces creation within the sandbox.
	pub disable_userns: bool,
}

impl Default for SandboxOptions {
	fn default() -> Self {
		Self {
			disable_userns: false,
		}
	}
}

pub use bind_mount_sandbox::*;
pub use managed_bind_mount_sandbox::*;
pub use mount_attributes::*;
pub use placeholders::*;
pub use upgrade::RequestHandle;

#[cfg(test)]
mod sandbox_integration_tests {
	use super::*;

	/// Try to create a low-level sandbox.  Nested user namespaces are
	/// unavailable in many CI/build environments (and may be blocked by
	/// AppArmor); when setup fails we skip the test rather than fail, so
	/// these privileged integration tests are a no-op where they can't
	/// run but still exercise the m1 mount logic where they can.
	fn try_new_sandbox() -> Option<BindMountSandbox> {
		match BindMountSandbox::new(SandboxOptions::default()) {
			Ok(sb) => Some(sb),
			Err(e) => {
				eprintln!("skipping privileged sandbox test: setup failed: {e}");
				None
			}
		}
	}

	fn mountinfo_has_mountpoint(raw: &[u8], mp: &[u8]) -> bool {
		mountinfo::parse_mountinfo(raw)
			.iter()
			.any(|e| e.mount_point.as_encoded_bytes() == mp)
	}

	/// Exercise `read_m1_mountinfo` + `park_to_scratch` +
	/// `restore_from_scratch`: a mount parked into the hidden scratch
	/// tmpfs disappears from its original mountpoint, and restoring it
	/// brings the same mount back to that path.
	#[test]
	fn park_and_restore_roundtrip() {
		let Some(sb) = try_new_sandbox() else {
			return;
		};
		sb.mount_host_into_sandbox_impl(c"/etc", c"/etc", MountAttributes::ro(), false, true)
			.expect("mount /etc");

		let before = sb.read_m1_mountinfo().expect("read mountinfo");
		assert!(
			mountinfo_has_mountpoint(&before, b"/etc"),
			"/etc should be mounted before parking"
		);

		sb.park_to_scratch(c"/etc", c"park-test")
			.expect("park /etc");
		let parked = sb.read_m1_mountinfo().expect("read mountinfo after park");
		assert!(
			!mountinfo_has_mountpoint(&parked, b"/etc"),
			"/etc must no longer be mounted after parking"
		);

		sb.restore_from_scratch(c"park-test", c"/etc")
			.expect("restore /etc");
		let after = sb
			.read_m1_mountinfo()
			.expect("read mountinfo after restore");
		assert!(
			mountinfo_has_mountpoint(&after, b"/etc"),
			"/etc must be mounted again after restore"
		);
	}
}
