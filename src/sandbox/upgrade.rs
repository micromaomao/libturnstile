//! §11 — per-request fd upgrade machinery.
//!
//! [`ManagedBindMountSandbox::new_request_handle`] wraps a yielded
//! `(AccessRequest, RequestContext)` pair into a [`RequestHandle`].  The
//! caller inspects the request, optionally mutates the mount layout via
//! `update_from_list` / `update_from_tree`, then calls
//! [`RequestHandle::allow`] or [`RequestHandle::deny`].
//!
//! `allow()` transparently makes the traced process's view match the
//! live bind-mount layout, per the dispatch table in §11.2:
//!
//! * `openat`-family — re-resolve the abspath, open it fresh in m1 (so
//!   it resolves through the *current* layout), identity-check it, and
//!   hand the new fd to the app as the syscall's return value via
//!   `SECCOMP_IOCTL_NOTIF_ADDFD` (SEND).
//! * `chdir` / `fchdir` — preemptively ensure a mount exists on the
//!   target (cwd can't be upgraded after the fact, §11.5), then CONTINUE.
//! * any other `*at` with a real `dirfd` — if the dirfd is stale relative
//!   to the current layout (`mnt_id` mismatch), m1-open the dirfd's path,
//!   identity-check, and replace it in place (ADDFD SETFD), then CONTINUE.
//! * `fchmod` / `fchown` / `ftruncate` / `fsetxattr` / `fremovexattr` on
//!   a stale file fd — m1-open the path, identity-check, perform the op
//!   there, and return the result directly (no CONTINUE).
//! * anything else — CONTINUE.

use std::ffi::{CStr, CString, OsStr};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;

use libc::open_how;
use log::{debug, error, warn};

use crate::{
	AccessRequestError, RequestContext,
	access::{
		AccessRequest, Operation,
		fs::{ForeignFd, FsOperation, InodeId, ModifyFdKind, ModifyFdOperation},
	},
	syscalls::fs as syscalls_fs,
};

use super::{ManagedBindMountSandbox, ManagedMountPoint, MountAttributes};

/// Convert an absolute path (as bytes, no interior NUL) into a
/// NUL-terminated `CString`, or `None` if it contains a NUL byte.
fn to_cstring(bytes: &[u8]) -> Option<CString> {
	CString::new(bytes.to_vec()).ok()
}

impl ManagedBindMountSandbox {
	/// Wrap a request yielded by the tracer into a [`RequestHandle`]
	/// bound to this sandbox.  The handle's [`RequestHandle::allow`]
	/// performs the §11 fd-upgrade dispatch against this sandbox's live
	/// mount layout.
	pub fn new_request_handle<'s, 't>(
		&'s self,
		request: AccessRequest,
		req_ctx: RequestContext<'t>,
	) -> RequestHandle<'s, 't> {
		RequestHandle {
			sandbox: self,
			request,
			req_ctx,
		}
	}

	/// Look up the kernel `mnt_id` of the topmost tracked mount covering
	/// `sandbox_path`, if any.  Used to detect stale fds: an fd whose
	/// `statx().mnt_id` differs from this value is pinned to an
	/// older/detached mount and must be re-resolved through the current
	/// layout.
	fn expected_mnt_id(&self, sandbox_path: &OsStr) -> Option<u64> {
		let mt = self
			.current_mount_tree
			.lock()
			.expect("current_mount_tree lock poisoned");
		mt.find(sandbox_path, |_, _| true).map(|(_, mi)| mi.mnt_id)
	}

	/// Whether any tracked mount covers `sandbox_path`.
	fn is_covered(&self, sandbox_path: &OsStr) -> bool {
		self.current_mount_tree
			.lock()
			.expect("current_mount_tree lock poisoned")
			.find(sandbox_path, |_, _| true)
			.is_some()
	}

	/// Open `path` (absolute, in m1's view) with `how`, retrying once on
	/// failure or inode-identity mismatch.  When `expected` is `Some`,
	/// the freshly-opened fd's `(dev, ino)` must equal it (§11.3);
	/// otherwise the open is retried, and after two failures `None` is
	/// returned (the caller fails closed).
	fn m1_open_checked(
		&self,
		path: &CStr,
		how: &open_how,
		expected: Option<InodeId>,
	) -> Option<ForeignFd> {
		let mut attempts = 0u32;
		loop {
			match self.sandbox.open_in_m1(path, how) {
				Ok(fd) => match expected {
					None => return Some(fd),
					Some(exp) => match fd.inode_id() {
						Ok(id) if id == exp => return Some(fd),
						Ok(id) => {
							attempts += 1;
							debug!(
								"m1 reopen of {:?}: identity mismatch (expected {:?}, got {:?}), attempt {}",
								path, exp, id, attempts
							);
							if attempts >= 2 {
								error!(
									"m1 reopen of {:?}: identity check failed after retries; failing closed",
									path
								);
								return None;
							}
						}
						Err(e) => {
							attempts += 1;
							debug!("m1 reopen of {:?}: statx failed: {}", path, e);
							if attempts >= 2 {
								return None;
							}
						}
					},
				},
				Err(e) => {
					attempts += 1;
					debug!(
						"m1 reopen of {:?} failed: {}, attempt {}",
						path, e, attempts
					);
					if attempts >= 2 {
						return None;
					}
				}
			}
		}
	}

	/// The dispatch entry point used by [`RequestHandle::allow`].
	fn allow_request(
		&self,
		request: &AccessRequest,
		ctx: &mut RequestContext,
	) -> Result<(), AccessRequestError> {
		let Operation::FsOperation(fsop) = request.operation();
		let syscall = ctx.syscall();

		// openat-family: always substitute a fresh fd resolved through
		// the current layout.
		if let Some(params) = syscalls_fs::open_reopen_params(ctx)? {
			return self.allow_open(fsop, params, ctx);
		}

		// chdir/fchdir: preemptively ensure a covering mount (§11.5).
		if syscalls_fs::is_chdir(syscall) {
			return self.allow_chdir(fsop, ctx);
		}

		// File-fd metadata/content ops: proxy in m1 if the fd is stale.
		if let FsOperation::FsModifyFd(op) = fsop {
			return self.allow_modify_fd(op, ctx);
		}

		// Any other *at with a real dirfd: upgrade it in place if stale.
		let dfds = syscalls_fs::dfd_arg_indices(syscall);
		if !dfds.is_empty() {
			return self.allow_at_dirfds(&dfds, ctx);
		}

		ctx.send_continue()
	}

	/// `openat` / `openat2` / `open` / `creat`: re-open the abspath in m1
	/// with the requested flags and hand the fresh fd to the app.
	fn allow_open(
		&self,
		fsop: &FsOperation,
		params: syscalls_fs::ReopenParams,
		ctx: &mut RequestContext,
	) -> Result<(), AccessRequestError> {
		let FsOperation::FsOpen(op) = fsop else {
			// Shouldn't happen (open_reopen_params only matches
			// open-family syscalls, which always parse to FsOpen).
			return ctx.send_continue();
		};

		let abspath = match op.target.realpath() {
			Ok(p) => p,
			Err(e) => {
				warn!(
					"openat upgrade: cannot resolve abspath for {}: {} — continuing natively",
					op.target, e
				);
				return ctx.send_continue();
			}
		};
		let Some(abspath_c) = to_cstring(abspath.as_bytes()) else {
			return ctx.send_continue();
		};

		// For a fresh open the identity reference is what the app's own
		// path resolves to right now (post-grant); skip it when creating
		// (the leaf may not exist yet).
		let creating = params.flags & libc::O_CREAT as u64 != 0;
		let expected = if creating {
			None
		} else {
			op.target
				.open_target()
				.ok()
				.and_then(|fd| fd.inode_id().ok())
		};

		let how = build_open_how(&params);
		let fd = match self.m1_open_checked(&abspath_c, &how, expected) {
			Some(fd) => fd,
			None => {
				// Identity check failed after retries → fail closed.
				if !creating && expected.is_some() {
					return ctx.send_error(-libc::EIO);
				}
				// Open itself failed; let the kernel report the real
				// error by re-executing the syscall.
				return ctx.send_continue();
			}
		};

		let cloexec = params.flags & libc::O_CLOEXEC as u64 != 0;
		match ctx.install_fd_and_respond(fd.as_raw_fd(), cloexec) {
			Ok(newfd) => {
				debug!(
					"openat upgrade: installed fresh fd {} for {:?}",
					newfd, abspath_c
				);
				Ok(())
			}
			Err(e) => {
				if ctx.still_valid()? {
					Err(e)
				} else {
					Ok(())
				}
			}
		}
	}

	/// `chdir` / `fchdir`: ensure a covering mount exists before letting
	/// the syscall through (§11.5).  cwd cannot be upgraded after the
	/// fact, so the mount must be in place when the kernel sets `pwd`.
	fn allow_chdir(
		&self,
		fsop: &FsOperation,
		ctx: &mut RequestContext,
	) -> Result<(), AccessRequestError> {
		let FsOperation::FsChdir(target) = fsop else {
			return ctx.send_continue();
		};
		let abspath = match target.realpath() {
			Ok(p) => p,
			Err(e) => {
				warn!("chdir: cannot resolve abspath for {}: {}", target, e);
				return ctx.send_continue();
			}
		};
		let abspath_bytes = abspath.as_bytes();
		if abspath_bytes == b"/" || self.is_covered(OsStr::from_bytes(abspath_bytes)) {
			return ctx.send_continue();
		}
		// No covering mount: add one with chdir's effective attrs
		// (ro,noexec).  The host dentry is guaranteed to exist (the app
		// already established the chdir target), so host_path == abspath.
		if let Some(abspath_c) = to_cstring(abspath_bytes) {
			let mp = ManagedMountPoint {
				host_path: abspath_c,
				attrs: MountAttributes {
					readonly: true,
					noexec: true,
				},
			};
			if let Err(e) = self.add_or_update_mount(OsStr::from_bytes(abspath_bytes), mp) {
				warn!(
					"chdir: failed to add preemptive mount on {:?}: {}",
					abspath, e
				);
			} else {
				debug!("chdir: added preemptive ro,noexec mount on {:?}", abspath);
			}
		}
		ctx.send_continue()
	}

	/// Generic `*at` syscalls with a real `dirfd`: replace any stale
	/// dirfd in place so the kernel resolves the relative path through
	/// the current layout.
	fn allow_at_dirfds(
		&self,
		dfd_indices: &[u8],
		ctx: &mut RequestContext,
	) -> Result<(), AccessRequestError> {
		for &idx in dfd_indices {
			let raw = ctx.arg(idx as usize) as libc::c_int;
			if raw == libc::AT_FDCWD || raw < 0 {
				continue;
			}
			// Open the app's dirfd from /proc to inspect it.
			let app_fd = match ctx.arg_to_fd(idx as usize) {
				Ok(f) => f,
				Err(e) => {
					debug!("dirfd upgrade: cannot open app fd {}: {}", raw, e);
					continue;
				}
			};
			let cur_mnt = match app_fd.mnt_id() {
				Ok(m) => m,
				Err(e) => {
					debug!(
						"dirfd upgrade: statx(mnt_id) on app fd {} failed: {}",
						raw, e
					);
					continue;
				}
			};
			let sandbox_path = match app_fd.readlink() {
				Ok(p) => p,
				Err(e) => {
					debug!("dirfd upgrade: readlink of app fd {} failed: {}", raw, e);
					continue;
				}
			};
			match self.expected_mnt_id(&sandbox_path) {
				// Not stale, or no tracked covering mount to compare
				// against: leave the dirfd untouched.
				Some(exp) if exp != 0 && exp == cur_mnt => continue,
				Some(_) => {}
				None => continue,
			}
			let Some(path_c) = to_cstring(sandbox_path.as_bytes()) else {
				continue;
			};
			let expected = app_fd.inode_id().ok();
			let how = build_path_open_how();
			let m1fd = match self.m1_open_checked(&path_c, &how, expected) {
				Some(fd) => fd,
				// Per §11.3: on failure, skip the upgrade (plain CONTINUE
				// without replacement) rather than breaking the syscall.
				None => continue,
			};
			warn!(
				"upgrading stale dirfd {} ({:?}): mnt_id {} no longer current",
				raw, sandbox_path, cur_mnt
			);
			if let Err(e) = ctx.replace_fd(m1fd.as_raw_fd(), raw, false) {
				if ctx.still_valid()? {
					return Err(e);
				}
				return Ok(());
			}
		}
		ctx.send_continue()
	}

	/// `fchmod` / `fchown` / `ftruncate` / `fsetxattr` / `fremovexattr`:
	/// if the file fd is stale, perform the op in m1 against the current
	/// layout and return the result directly.
	fn allow_modify_fd(
		&self,
		op: &ModifyFdOperation,
		ctx: &mut RequestContext,
	) -> Result<(), AccessRequestError> {
		let app_fd = op.target.dfd();
		let cur_mnt = match app_fd.mnt_id() {
			Ok(m) => m,
			Err(_) => return ctx.send_continue(),
		};
		let sandbox_path = match app_fd.readlink() {
			Ok(p) => p,
			Err(_) => return ctx.send_continue(),
		};
		match self.expected_mnt_id(&sandbox_path) {
			Some(exp) if exp != 0 && exp == cur_mnt => return ctx.send_continue(),
			Some(_) => {}
			None => return ctx.send_continue(),
		}
		let Some(path_c) = to_cstring(sandbox_path.as_bytes()) else {
			return ctx.send_continue();
		};
		let expected = app_fd.inode_id().ok();
		let how = build_path_open_how();
		let m1fd = match self.m1_open_checked(&path_c, &how, expected) {
			Some(fd) => fd,
			None => return ctx.send_error(-libc::EIO),
		};
		match perform_modify(&op.kind, m1fd.as_raw_fd()) {
			Ok(()) => ctx.send_value(0),
			Err(errno) => ctx.send_error(-errno),
		}
	}
}

/// Build an `open_how` for faithfully re-opening an `openat`-family
/// target in m1.  Resolution is confined to m1's root, preserving any
/// `RESOLVE_NO_SYMLINKS` the app requested via `openat2`.
fn build_open_how(params: &syscalls_fs::ReopenParams) -> open_how {
	let mut how: open_how = unsafe { std::mem::zeroed() };
	how.flags = params.flags;
	how.mode = params.mode;
	how.resolve = libc::RESOLVE_IN_ROOT | (params.resolve & libc::RESOLVE_NO_SYMLINKS);
	how
}

/// Build an `open_how` for an `O_PATH` handle used purely to re-resolve a
/// path in m1 (for dirfd / file-fd upgrades).
fn build_path_open_how() -> open_how {
	let mut how: open_how = unsafe { std::mem::zeroed() };
	how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
	how.resolve = libc::RESOLVE_IN_ROOT;
	how
}

/// Re-issue a file-fd modifying op against the m1-opened handle `fd`
/// (an `O_PATH` fd, addressed via its `/proc/self/fd` magic symlink so
/// the op resolves through m1's mount).  Returns the `errno` on failure.
fn perform_modify(kind: &ModifyFdKind, fd: libc::c_int) -> Result<(), libc::c_int> {
	// `fd` is a freshly m1-opened O_PATH handle returned by
	// `m1_open_checked`, so it is always a valid non-negative descriptor;
	// its /proc/self/fd magic symlink redirects the path-based ops below
	// through m1's mount.
	debug_assert!(fd >= 0);
	let proc_path = format!("/proc/self/fd/{}\0", fd);
	let p = proc_path.as_ptr() as *const libc::c_char;
	let ret = unsafe {
		match kind {
			ModifyFdKind::Chmod { mode } => {
				libc::fchmodat(libc::AT_FDCWD, p, *mode as libc::mode_t, 0)
			}
			ModifyFdKind::Chown { uid, gid } => libc::fchownat(libc::AT_FDCWD, p, *uid, *gid, 0),
			ModifyFdKind::Truncate { length } => libc::truncate(p, *length as libc::off_t),
			ModifyFdKind::SetXattr { name, value, flags } => libc::setxattr(
				p,
				name.as_ptr(),
				value.as_ptr() as *const libc::c_void,
				value.len(),
				*flags,
			) as libc::c_int,
			ModifyFdKind::RemoveXattr { name } => libc::removexattr(p, name.as_ptr()),
		}
	};
	if ret < 0 {
		Err(std::io::Error::last_os_error()
			.raw_os_error()
			.unwrap_or(libc::EIO))
	} else {
		Ok(())
	}
}

/// A handle to a single yielded access request, bound to the sandbox it
/// came from.  Inspect [`Self::request`], optionally update the mount
/// layout, then call [`Self::allow`] or [`Self::deny`].
///
/// Dropping the handle without responding auto-continues the syscall
/// (inherited from the underlying [`RequestContext`]).
pub struct RequestHandle<'s, 't> {
	sandbox: &'s ManagedBindMountSandbox,
	request: AccessRequest,
	req_ctx: RequestContext<'t>,
}

impl<'s, 't> RequestHandle<'s, 't> {
	/// The parsed access request.
	pub fn request(&self) -> &AccessRequest {
		&self.request
	}

	/// The underlying request context (process info, validity, memory
	/// access).
	pub fn req_ctx(&self) -> &RequestContext<'t> {
		&self.req_ctx
	}

	/// Mutable access to the underlying request context, e.g. to check
	/// [`RequestContext::still_valid`] or read
	/// [`RequestContext::comm`] / [`RequestContext::pid`] while applying
	/// policy.
	pub fn req_ctx_mut(&mut self) -> &mut RequestContext<'t> {
		&mut self.req_ctx
	}

	/// Allow the request, transparently upgrading or proxying fds so the
	/// traced process's view matches the live mount layout (§11.2).
	pub fn allow(mut self) -> Result<(), AccessRequestError> {
		// Disjoint field borrows: `request` immutably, `req_ctx` mutably.
		self.sandbox.allow_request(&self.request, &mut self.req_ctx)
	}

	/// Deny the request, failing the syscall with `errno`.
	pub fn deny(mut self, errno: libc::c_int) -> Result<(), AccessRequestError> {
		self.req_ctx.send_error(-errno.abs())
	}
}
