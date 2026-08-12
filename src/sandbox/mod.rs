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

pub use bind_mount_sandbox::*;
pub use managed_bind_mount_sandbox::*;
pub use mount_attributes::*;
pub use placeholders::*;
pub use upgrade::RequestHandle;

#[cfg(test)]
mod sandbox_integration_tests {
	use super::*;
	use std::{ffi::CString, ffi::OsStr, os::unix::ffi::OsStrExt};

	/// Try to create a low-level sandbox.  Nested user namespaces are
	/// unavailable in many CI/build environments (and may be blocked by
	/// AppArmor); when setup fails we skip the test rather than fail, so
	/// these privileged integration tests are a no-op where they can't
	/// run but still exercise the m1 mount logic where they can.
	fn try_new_sandbox() -> Option<BindMountSandbox> {
		match BindMountSandbox::new(false) {
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

	/// Return the bind source (`root` field) of the topmost mount at `mp`,
	/// if any.
	fn mountinfo_root_for(raw: &[u8], mp: &[u8]) -> Option<Vec<u8>> {
		mountinfo::parse_mountinfo(raw)
			.iter()
			.filter(|e| e.mount_point.as_encoded_bytes() == mp)
			.last()
			.map(|e| e.root.as_bytes().to_vec())
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
		sb.mount_host_into_sandbox_impl(
			c"/etc",
			c"/etc",
			MountAttributes::ro(),
			false,
			false,
			true,
		)
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

	/// Exercise `unmount_covering`: a parent mount with a child
	/// sub-mount is unmounted while the child's `struct mount` identity is
	/// preserved.  Afterwards the parent is gone but the child
	/// is restored on the revealed placeholder layer.
	#[test]
	fn unmount_covering_preserves_child() {
		let Some(sb) = try_new_sandbox() else {
			return;
		};
		// Parent bind: /etc at /p (creates the /p placeholder).
		sb.mount_host_into_sandbox_impl(c"/etc", c"/p", MountAttributes::ro(), false, false, true)
			.expect("mount parent /p");
		// Child bind: /etc at /p/ssl (mountpoint /etc/ssl exists through the
		// /p bind; also creates a /p/ssl placeholder on the revealed layer).
		sb.mount_host_into_sandbox_impl(
			c"/etc",
			c"/p/ssl",
			MountAttributes::ro(),
			false,
			false,
			true,
		)
		.expect("mount child /p/ssl");

		let before = sb.read_m1_mountinfo().expect("read mountinfo");
		assert!(
			mountinfo_has_mountpoint(&before, b"/p"),
			"/p should be mounted before unmount_covering"
		);
		assert!(
			mountinfo_has_mountpoint(&before, b"/p/ssl"),
			"/p/ssl should be mounted before unmount_covering"
		);

		let unmounted = sb
			.unmount_covering(c"/p", &[CString::new("/p/ssl").unwrap()])
			.expect("unmount_covering /p");
		assert!(
			unmounted,
			"/p should have been unmounted (nothing holds it)"
		);

		let after = sb.read_m1_mountinfo().expect("read mountinfo after");
		assert!(
			!mountinfo_has_mountpoint(&after, b"/p"),
			"/p must be gone after unmount_covering"
		);
		assert!(
			mountinfo_has_mountpoint(&after, b"/p/ssl"),
			"/p/ssl child mount must be preserved after unmount_covering"
		);
	}

	/// End-to-end check through the managed reconcile API: removing a
	/// parent mount that has a still-desired child preserves the child
	/// (the `Removed` branch routes through `unmount_covering`).
	#[test]
	fn managed_remove_preserves_child_mount() {
		let msb = match ManagedBindMountSandbox::new(false) {
			Ok(s) => s,
			Err(e) => {
				eprintln!("skipping privileged managed test: setup failed: {e}");
				return;
			}
		};
		let mp = ManagedMountPoint {
			host_path: CString::new("/etc").unwrap(),
			attrs: MountAttributes::ro(),
		};
		msb.add_or_update_mount(OsStr::new("/p"), mp.clone())
			.expect("add /p");
		msb.add_or_update_mount(OsStr::new("/p/ssl"), mp.clone())
			.expect("add /p/ssl");

		let before = msb.sandbox.read_m1_mountinfo().expect("mountinfo");
		assert!(mountinfo_has_mountpoint(&before, b"/p"), "/p mounted");
		assert!(
			mountinfo_has_mountpoint(&before, b"/p/ssl"),
			"/p/ssl mounted"
		);

		msb.remove_mount(OsStr::new("/p")).expect("remove /p");

		let after = msb.sandbox.read_m1_mountinfo().expect("mountinfo after");
		assert!(
			!mountinfo_has_mountpoint(&after, b"/p"),
			"/p must be removed"
		);
		assert!(
			mountinfo_has_mountpoint(&after, b"/p/ssl"),
			"/p/ssl child must be preserved through parent removal"
		);
	}

	/// A host_path change is handled as a split (Removed then Added).
	/// The mountpoint must survive and rebind to the new host source.
	#[test]
	fn managed_host_path_change_rebinds() {
		let msb = match ManagedBindMountSandbox::new(false) {
			Ok(s) => s,
			Err(e) => {
				eprintln!("skipping privileged managed test: setup failed: {e}");
				return;
			}
		};
		msb.add_or_update_mount(
			OsStr::new("/p"),
			ManagedMountPoint {
				host_path: CString::new("/etc").unwrap(),
				attrs: MountAttributes::ro(),
			},
		)
		.expect("add /p -> /etc");
		let before = msb.sandbox.read_m1_mountinfo().expect("mountinfo");
		assert_eq!(
			mountinfo_root_for(&before, b"/p").as_deref(),
			Some(&b"/etc"[..]),
			"/p should bind /etc initially"
		);

		// Change the host source for the same sandbox path.
		msb.add_or_update_mount(
			OsStr::new("/p"),
			ManagedMountPoint {
				host_path: CString::new("/usr").unwrap(),
				attrs: MountAttributes::ro(),
			},
		)
		.expect("rebind /p -> /usr");

		let after = msb.sandbox.read_m1_mountinfo().expect("mountinfo after");
		assert!(
			mountinfo_has_mountpoint(&after, b"/p"),
			"/p must still be mounted after host_path change"
		);
		assert_eq!(
			mountinfo_root_for(&after, b"/p").as_deref(),
			Some(&b"/usr"[..]),
			"/p should bind /usr after the host_path change"
		);
	}
}
