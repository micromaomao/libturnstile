//! Per-request fd upgrade machinery.
//!
//! [`ManagedBindMountSandbox::new_request_handle`] wraps a yielded
//! `(AccessRequest, RequestContext)` pair into a [`RequestHandle`].  The
//! caller inspects the request, optionally mutates the mount layout via
//! `update_from_list` / `update_from_tree`, then calls
//! [`RequestHandle::allow`] or [`RequestHandle::deny`].
//!
//! `allow()` transparently makes the traced process's view match the
//! live bind-mount layout:
//!
//! * `openat`-family - re-resolve the abspath, open it fresh in m1 (so
//!   it resolves through the *current* layout), identity-check it, and
//!   hand the new fd to the app as the syscall's return value via
//!   `SECCOMP_IOCTL_NOTIF_ADDFD` (SEND).
//! * `chdir` / `fchdir` - preemptively ensure a mount exists on the
//!   target (cwd can't be upgraded after the fact), then CONTINUE.
//! * any other access governed by a held fd whose mount is stale (the
//!   dirfd of an `*at(dirfd, relpath)`, or the target fd of an
//!   `f*` / `*at(fd, "", AT_EMPTY_PATH)` metadata op) - the choice
//!   between swapping the fd and proxying the op comes down to whether
//!   the held fd is *upgradable* (see [`fd_upgrade_kind`]).  An
//!   **upgradable** fd (a directory, or an `O_PATH` fd) carries no
//!   read/write position to lose, so we m1-open its abspath,
//!   identity-check, and swap a fresh fd in at the same number
//!   (`ADDFD SETFD`) before CONTINUE - the kernel then resolves / acts
//!   through the live layout (a swapped `O_PATH` fd reproduces the
//!   syscall's native `O_PATH` semantics against that layout).  An
//!   **unupgradable**
//!   fd (a regular file, …) would lose its `f_pos`/open state on a swap,
//!   so for the metadata ops we instead perform the op in m1 and return
//!   the result directly (no swap, no CONTINUE).  `ftruncate` is exempt
//!   entirely (always CONTINUE): it needs a writable fd, which can only
//!   sit on a still-writable mount.
//! * anything else - CONTINUE.

use std::ffi::{CStr, CString, OsStr};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::sync::OnceLock;

use libc::open_how;
use libseccomp::ScmpSyscall;
use log::{debug, error, info, warn};

use crate::{
	AccessRequestError, RequestContext,
	access::{
		AccessRequest, Operation,
		fs::{
			ChmodOperation, ChownOperation, ForeignFd, FsOperation, FsTarget, InodeId,
			OriginalHandle, RemoveXattrOperation, SetXattrOperation, TruncateOperation,
		},
	},
	syscalls::fs as syscalls_fs,
};

use super::{ManagedBindMountSandbox, ManagedMountPoint, MountAttributes};

/// Convert an absolute path (as bytes, no interior NUL) into a
/// NUL-terminated `CString`, or `None` if it contains a NUL byte.
fn to_cstring(bytes: &[u8]) -> Option<CString> {
	CString::new(bytes.to_vec()).ok()
}

/// Cache of the syscall numbers the fd-upgrade dispatch needs to
/// special-case, resolved once for the native architecture.
struct UpgradeSyscalls {
	open: Option<ScmpSyscall>,
	openat: Option<ScmpSyscall>,
	openat2: Option<ScmpSyscall>,
	creat: Option<ScmpSyscall>,
	chdir: Option<ScmpSyscall>,
	fchdir: Option<ScmpSyscall>,
}

fn upgraded_syscalls() -> &'static UpgradeSyscalls {
	static ONCE: OnceLock<UpgradeSyscalls> = OnceLock::new();
	ONCE.get_or_init(|| {
		let n = |name: &str| ScmpSyscall::from_name(name).ok();
		UpgradeSyscalls {
			open: n("open"),
			openat: n("openat"),
			openat2: n("openat2"),
			creat: n("creat"),
			chdir: n("chdir"),
			fchdir: n("fchdir"),
		}
	})
}

/// How a freshly-resolved `openat`-family syscall should be re-opened in
/// m1: the open flags, creation mode, and `openat2` resolve flags (0 for
/// the non-`openat2` variants).
#[derive(Debug, Clone, Copy)]
struct ReopenParams {
	flags: u64,
	mode: u64,
	resolve: u64,
}

/// If the request's syscall is an `open`-family syscall, return the
/// parameters needed to faithfully re-open the target in m1.  Reuses the
/// same argument layout the request-parsing handlers use, rather than
/// re-parsing.
fn open_reopen_params(
	req: &mut RequestContext,
) -> Result<Option<ReopenParams>, AccessRequestError> {
	let s = upgraded_syscalls();
	let syscall = req.syscall();
	if Some(syscall) == s.open {
		Ok(Some(ReopenParams {
			flags: req.arg(1),
			mode: req.arg(2),
			resolve: 0,
		}))
	} else if Some(syscall) == s.openat {
		Ok(Some(ReopenParams {
			flags: req.arg(2),
			mode: req.arg(3),
			resolve: 0,
		}))
	} else if Some(syscall) == s.openat2 {
		let open_how_ptr = req.arg(2) as *const libc::open_how;
		let how = req.value_from_target_memory(open_how_ptr)?;
		Ok(Some(ReopenParams {
			flags: how.flags,
			mode: how.mode,
			resolve: how.resolve,
		}))
	} else if Some(syscall) == s.creat {
		Ok(Some(ReopenParams {
			flags: (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as u64,
			mode: req.arg(1),
			resolve: 0,
		}))
	} else {
		Ok(None)
	}
}

/// Whether `syscall` is `chdir` or `fchdir`.
fn is_chdir(syscall: ScmpSyscall) -> bool {
	let s = upgraded_syscalls();
	Some(syscall) == s.chdir || Some(syscall) == s.fchdir
}

impl ManagedBindMountSandbox {
	/// Wrap a request yielded by the tracer into a [`RequestHandle`]
	/// bound to this sandbox.  The handle's [`RequestHandle::allow`]
	/// performs the fd-upgrade dispatch against this sandbox's live
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
	/// the freshly-opened fd's `(dev, ino)` must equal it;
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

	/// If the held fd `app_fd` is *stale* — its current `mnt_id` differs
	/// from the tracked mount covering its path — return that sandbox path
	/// (as a `CString`) and the fd's inode identity, ready for an m1
	/// reopen.  Returns `None` when there is nothing to fix: the path is
	/// not covered by a tracked mount, the fd's mount is already current,
	/// or the fd cannot be inspected.
	fn stale_held_fd_target(&self, app_fd: &ForeignFd) -> Option<(CString, Option<InodeId>)> {
		let cur_mnt = app_fd.mnt_id().ok()?;
		let sandbox_path = app_fd.readlink().ok()?;
		match self.expected_mnt_id(&sandbox_path) {
			// Already current, or no tracked covering mount to compare
			// against: nothing to fix.
			Some(exp) if exp != 0 && exp == cur_mnt => return None,
			Some(_) => {}
			None => return None,
		}
		let path_c = to_cstring(sandbox_path.as_bytes())?;
		let expected = app_fd.inode_id().ok();
		Some((path_c, expected))
	}

	/// Swap a fresh handle, opened on the live mount layout, in at the app
	/// fd number `raw`.  `how` selects the handle's character so the
	/// swapped fd behaves like the original (`build_dir_open_how` for a
	/// real directory fd so it stays usable for `getdents`, or
	/// `build_path_open_how` for an `O_PATH` fd so it keeps its `O_PATH`
	/// semantics).  Shared by the stale-`*at`-dirfd path and the
	/// upgradable target fd of an `f*` / `AT_EMPTY_PATH` op.
	fn swap_stale_fd(
		&self,
		ctx: &mut RequestContext,
		raw: libc::c_int,
		path_c: &CStr,
		expected: Option<InodeId>,
		how: &open_how,
	) -> Result<FdSwapOutcome, AccessRequestError> {
		let m1fd = match self.m1_open_checked(path_c, how, expected) {
			Some(fd) => fd,
			// Failed identity check: skip the swap (leave the fd in place)
			// rather than breaking the syscall.
			None => return Ok(FdSwapOutcome::NoChange),
		};
		warn!(
			"upgrading stale held fd {} ({:?}): mount no longer current",
			raw, path_c
		);
		if let Err(e) = ctx.replace_fd(m1fd.as_raw_fd(), raw, false) {
			if ctx.still_valid()? {
				return Err(e);
			}
			return Ok(FdSwapOutcome::RequestGone);
		}
		Ok(FdSwapOutcome::Swapped)
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
		if let Some(params) = open_reopen_params(ctx)? {
			debug!("Handling open request {:?}", request.operation());
			return self.allow_open(fsop, params, ctx);
		}

		// chdir/fchdir: preemptively ensure a covering mount before the
		// kernel resolves cwd (cwd can't be upgraded after the fact).
		if is_chdir(syscall) {
			debug!("Handling chdir request {:?}", request.operation());
			return self.allow_chdir(fsop, ctx);
		}

		// A metadata/content op whose target *is* an already-open
		// descriptor (an `f*` call, or an `*at` with `AT_EMPTY_PATH`):
		// the access is governed by that held fd, so whether we swap it
		// or proxy the op depends on the fd's upgradability, not on the
		// fact that it carries an empty path.  Path-based variants instead
		// carry no target fd; they resolve afresh when the syscall continues
		// (any `dirfd` they do carry is handled by the dirfd-upgrade path
		// below).
		if let Some(target) = modify_op_held_fd_target(fsop) {
			debug!("Handling modify-fd request {:?}", request.operation());
			return self.allow_modify_fd(fsop, target, ctx);
		}

		// Any other `*at` with a real dirfd: the dirfd governs the
		// resolution, so upgrade it in place if its mount is stale.
		let dfds = syscalls_fs::dfd_arg_indices(syscall);
		if !dfds.is_empty() {
			debug!("Handling *at request {:?}", request.operation());
			return self.allow_at_dirfds(&dfds, ctx);
		}

		ctx.send_continue()
	}

	/// `openat` / `openat2` / `open` / `creat`: re-open the abspath in m1
	/// with the requested flags and hand the fresh fd to the app.
	fn allow_open(
		&self,
		fsop: &FsOperation,
		params: ReopenParams,
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
		debug!(
			"openat(fd => {:?}, {:?}) abspath = {:?}",
			op.target.dfd().readlink(),
			op.target.path(),
			abspath
		);
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
	/// the syscall through.  cwd cannot be upgraded after the fact (there
	/// is no fd to swap), so the mount must be in place when the kernel
	/// sets `pwd`.
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
	/// the current layout.  A dirfd that resolves a relative path is by
	/// definition a directory (or `O_PATH`) fd, i.e. always upgradable;
	/// the upgradability check is kept for robustness (a non-directory fd
	/// passed here would fail `ENOTDIR` natively if left untouched).  The
	/// swapped-in fd preserves the original's character (real directory vs
	/// `O_PATH`), so e.g. a later `getdents` on a real-directory dirfd
	/// keeps working.
	fn allow_at_dirfds(
		&self,
		dfd_indices: &[u8],
		ctx: &mut RequestContext,
	) -> Result<(), AccessRequestError> {
		let pid = ctx.pid();
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
			// Only swap an upgradable fd; a regular-file dirfd is a native
			// `ENOTDIR`, so leave it untouched.
			let kind = fd_upgrade_kind(pid, raw, &app_fd);
			if !kind.is_upgradable() {
				continue;
			}
			let Some((path_c, expected)) = self.stale_held_fd_target(&app_fd) else {
				continue;
			};
			// Preserve the dirfd's character: a real directory fd must stay
			// a real directory (else a later `getdents` on it would
			// `EBADF`), an `O_PATH` dirfd stays `O_PATH`.
			let how = swap_open_how(kind);
			match self.swap_stale_fd(ctx, raw, &path_c, expected, &how)? {
				FdSwapOutcome::RequestGone => return Ok(()),
				FdSwapOutcome::NoChange | FdSwapOutcome::Swapped => {}
			}
		}
		ctx.send_continue()
	}

	/// A metadata/content op whose target *is* an already-open
	/// descriptor (`fchmod` / `fchown` / `fsetxattr` / `fremovexattr`, or
	/// any `*at` modify call with `AT_EMPTY_PATH`): make the op act
	/// against the live layout.  How depends on the held fd:
	///
	/// * an **upgradable** fd (directory or `O_PATH`) is swapped in place
	///   for a fresh one resolved on the live layout, then CONTINUE - so
	///   the op acts through the current mount (the swapped `O_PATH` fd
	///   reproduces the syscall's native `O_PATH` semantics, be that
	///   `EBADF` for `fchmod` or a valid `AT_EMPTY_PATH` `fchownat`);
	/// * an **unupgradable** fd (a regular file, …) would lose its
	///   `f_pos`/open state on a swap, so the op is performed in m1 and
	///   the result returned directly.
	///
	/// `ftruncate` is exempt: it needs a writable fd, which can only have
	/// been opened on a still-writable mount, so CONTINUE acts correctly.
	fn allow_modify_fd(
		&self,
		fsop: &FsOperation,
		target: &FsTarget,
		ctx: &mut RequestContext,
	) -> Result<(), AccessRequestError> {
		// `ftruncate` needs a writable fd; a writable fd implies a
		// still-writable mount, so it is never stale in a way we must
		// fix - always CONTINUE.
		if matches!(fsop, FsOperation::FsTruncate(_)) {
			return ctx.send_continue();
		}

		let app_fd = target.dfd();
		// The app's raw fd number, needed to swap an upgradable fd in
		// place.  Without a real fd number (e.g. `AT_FDCWD`, whose cwd is
		// kept current by the chdir path) there is nothing to address, so
		// CONTINUE.
		let OriginalHandle::Fd(target_fd) = target.get_original_handle() else {
			return ctx.send_continue();
		};

		// Nothing to fix unless the held fd's mount is stale.
		let Some((path_c, expected)) = self.stale_held_fd_target(app_fd) else {
			return ctx.send_continue();
		};

		let kind = fd_upgrade_kind(ctx.pid(), target_fd, app_fd);
		if kind.is_upgradable() {
			// A directory / `O_PATH` target carries no `f_pos`/open state to
			// lose, so swap a fresh kind-preserving fd in at the same number
			// and CONTINUE — identical to the stale-`*at`-dirfd path (an
			// `fchmod(dirfd)` is just `fchmodat(dirfd, "", AT_EMPTY_PATH)`).
			// A swapped `O_PATH` fd reproduces the syscall's native `O_PATH`
			// semantics against the live mount (e.g. `EBADF` for `fchmod`,
			// a valid `AT_EMPTY_PATH` `fchownat`).
			let how = swap_open_how(kind);
			return match self.swap_stale_fd(ctx, target_fd, &path_c, expected, &how)? {
				FdSwapOutcome::RequestGone => Ok(()),
				FdSwapOutcome::NoChange | FdSwapOutcome::Swapped => ctx.send_continue(),
			};
		}

		// Unupgradable (a regular file): a swap would clobber its
		// `f_pos`/open state, so proxy the op in m1 against the live
		// layout instead.
		let how = build_path_open_how();
		let m1fd = match self.m1_open_checked(&path_c, &how, expected) {
			Some(fd) => fd,
			None => return ctx.send_error(-libc::EIO),
		};
		match perform_modify(fsop, m1fd.as_raw_fd()) {
			Ok(()) => ctx.send_value(0),
			Err(errno) => ctx.send_error(-errno),
		}
	}
}

/// Build an `open_how` for faithfully re-opening an `openat`-family
/// target in m1.  Resolution is confined to m1's root, preserving any
/// `RESOLVE_NO_SYMLINKS` the app requested via `openat2`.
fn build_open_how(params: &ReopenParams) -> open_how {
	let mut how: open_how = unsafe { std::mem::zeroed() };
	how.flags = params.flags;
	how.mode = params.mode;
	how.resolve = libc::RESOLVE_IN_ROOT | (params.resolve & libc::RESOLVE_NO_SYMLINKS);
	how
}

/// Build an `open_how` for an `O_PATH` handle used purely to re-resolve a
/// path in m1 (for dirfd / `O_PATH` fd swaps and for the proxy path).
fn build_path_open_how() -> open_how {
	let mut how: open_how = unsafe { std::mem::zeroed() };
	how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
	how.resolve = libc::RESOLVE_IN_ROOT;
	how
}

/// Build an `open_how` for a real (non-`O_PATH`) directory handle opened
/// in m1, used to swap a stale real-directory fd — an `*at` dirfd, or the
/// directory target of an `f*` / `AT_EMPTY_PATH` op — so the swapped fd
/// keeps working (e.g. for `getdents`) and the op runs against the live
/// mount.
fn build_dir_open_how() -> open_how {
	let mut how: open_how = unsafe { std::mem::zeroed() };
	how.flags = (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
	how.resolve = libc::RESOLVE_IN_ROOT;
	how
}

/// How a stale app-held fd that governs an access can be made to reflect
/// the live mount layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FdUpgradeKind {
	/// An `O_PATH` fd.  It carries no read/write position, so it can be
	/// swapped for a fresh `O_PATH` fd resolved on the live layout; the
	/// swapped fd then reproduces the syscall's native `O_PATH` semantics
	/// (e.g. `EBADF` for `fchmod`, a valid `AT_EMPTY_PATH` `fchownat`)
	/// against the current mount.
	OPath,
	/// A directory fd.  Swappable for a fresh directory fd resolved on
	/// the live layout (only an in-progress `getdents` cursor is lost).
	Directory,
	/// A regular-file (or other) fd.  Swapping would clobber its
	/// `f_pos`/open state, so a stale one must be proxied in m1 instead.
	Unupgradable,
}

impl FdUpgradeKind {
	/// Whether a stale fd of this kind can be swapped in place (rather
	/// than needing a proxy).
	fn is_upgradable(self) -> bool {
		matches!(self, FdUpgradeKind::OPath | FdUpgradeKind::Directory)
	}
}

/// The `open_how` to swap in for an upgradable fd of `kind`, chosen to
/// preserve the original fd's character.  Must only be called for an
/// upgradable kind.
fn swap_open_how(kind: FdUpgradeKind) -> open_how {
	match kind {
		// Keep `O_PATH` semantics (e.g. `EBADF` for `fchmod`, a valid
		// `AT_EMPTY_PATH` `fchownat`) against the live mount.
		FdUpgradeKind::OPath => build_path_open_how(),
		// A real directory handle so the swapped fd stays usable for
		// `getdents` and as an `*at` base.
		FdUpgradeKind::Directory => build_dir_open_how(),
		FdUpgradeKind::Unupgradable => {
			debug_assert!(false, "swap_open_how called on an unupgradable fd");
			build_path_open_how()
		}
	}
}

/// Outcome of an in-place swap of a stale held fd (see
/// [`ManagedBindMountSandbox::swap_stale_fd`]).
enum FdSwapOutcome {
	/// Nothing changed — the identity check failed, so the original fd is
	/// left in place; continue the syscall.
	NoChange,
	/// A fresh, kind-preserving fd was swapped in at the same number.
	Swapped,
	/// The request is no longer valid (the traced process is gone or its
	/// response was already consumed); the caller should return `Ok(())`.
	RequestGone,
}

/// Classify the app-held fd `raw` (belonging to process `pid`) for the
/// upgrade path.  `O_PATH`-ness is read from `/proc/<pid>/fdinfo/<raw>`
/// (the `flags:` field preserves `O_PATH`); directory-ness from `statx`
/// on `app_fd` (a `/proc`-opened handle to the same fd).  Any read
/// failure conservatively classifies the fd as unupgradable so it is
/// proxied / left untouched rather than swapped.
fn fd_upgrade_kind(pid: libc::pid_t, raw: libc::c_int, app_fd: &ForeignFd) -> FdUpgradeKind {
	if app_fd_is_o_path(pid, raw) {
		return FdUpgradeKind::OPath;
	}
	match app_fd.is_dir() {
		Ok(true) => FdUpgradeKind::Directory,
		_ => FdUpgradeKind::Unupgradable,
	}
}

/// Whether the app fd `raw` of process `pid` was opened with `O_PATH`,
/// read from the `flags:` field (octal `file->f_flags`) of
/// `/proc/<pid>/fdinfo/<raw>`.  Returns `false` if the file cannot be
/// read or parsed.
fn app_fd_is_o_path(pid: libc::pid_t, raw: libc::c_int) -> bool {
	let path = format!("/proc/{}/fdinfo/{}", pid, raw);
	let Ok(content) = std::fs::read_to_string(&path) else {
		return false;
	};
	for line in content.lines() {
		if let Some(rest) = line.strip_prefix("flags:")
			&& let Ok(flags) = i32::from_str_radix(rest.trim(), 8)
		{
			return flags & libc::O_PATH != 0;
		}
	}
	false
}

/// If `fsop` is one of the metadata/content-modifying operations and its
/// target refers directly to an already-open descriptor (an `f*` call or
/// an `*at` call with `AT_EMPTY_PATH`), return that target.  The held fd
/// governs the access, so the upgrade path decides per its upgradability
/// whether to swap it or proxy the op.  Path-based variants return `None`
/// (they resolve afresh when the syscall continues).
fn modify_op_held_fd_target(fsop: &FsOperation) -> Option<&FsTarget> {
	let target = match fsop {
		FsOperation::FsChmod(ChmodOperation { target, .. })
		| FsOperation::FsChown(ChownOperation { target, .. })
		| FsOperation::FsTruncate(TruncateOperation { target, .. })
		| FsOperation::FsSetXattr(SetXattrOperation { target, .. })
		| FsOperation::FsRemoveXattr(RemoveXattrOperation { target, .. }) => target,
		_ => return None,
	};
	target.is_empty_path().then_some(target)
}

/// Re-issue a metadata/content-modifying op against the m1-opened handle
/// `fd` (an `O_PATH` fd, addressed via its `/proc/self/fd` magic symlink
/// so the op resolves through m1's mount).  Returns the `errno` on
/// failure.  Only the unupgradable (regular-file) `f*` variants are
/// proxied; other `FsOperation`s are never passed here.
fn perform_modify(fsop: &FsOperation, fd: libc::c_int) -> Result<(), libc::c_int> {
	// `fd` is a freshly m1-opened O_PATH handle returned by
	// `m1_open_checked`, so it is always a valid non-negative descriptor;
	// its /proc/self/fd magic symlink redirects the path-based ops below
	// through m1's mount.
	debug_assert!(fd >= 0);
	let proc_path = format!("/proc/self/fd/{}\0", fd);
	let p = proc_path.as_ptr() as *const libc::c_char;
	let ret = unsafe {
		match fsop {
			FsOperation::FsChmod(ChmodOperation { mode, .. }) => {
				libc::fchmodat(libc::AT_FDCWD, p, *mode as libc::mode_t, 0)
			}
			FsOperation::FsChown(ChownOperation { uid, gid, .. }) => {
				libc::fchownat(libc::AT_FDCWD, p, *uid, *gid, 0)
			}
			FsOperation::FsTruncate(TruncateOperation { length, .. }) => {
				libc::truncate(p, *length as libc::off_t)
			}
			FsOperation::FsSetXattr(SetXattrOperation {
				name, value, flags, ..
			}) => libc::setxattr(
				p,
				name.as_ptr(),
				value.as_ptr() as *const libc::c_void,
				value.len(),
				*flags,
			) as libc::c_int,
			FsOperation::FsRemoveXattr(RemoveXattrOperation { name, .. }) => {
				libc::removexattr(p, name.as_ptr())
			}
			// `allow_modify_fd` only calls this for the variants above;
			// any other op reaching here is a programming error.  Fail
			// closed rather than panicking inside the supervisor.
			_ => {
				debug_assert!(false, "perform_modify called with non-modify op {:?}", fsop);
				return Err(libc::EIO);
			}
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
	/// traced process's view matches the live mount layout.
	///
	/// If the request requires any additional mounts, the caller must have
	/// already added them.
	pub fn allow(mut self) -> Result<(), AccessRequestError> {
		// Disjoint field borrows: `request` immutably, `req_ctx` mutably.
		self.sandbox.allow_request(&self.request, &mut self.req_ctx)
	}

	/// Deny the request, failing the syscall with `errno`.
	pub fn deny(mut self, errno: libc::c_int) -> Result<(), AccessRequestError> {
		self.req_ctx.send_error(-errno.abs())
	}
}
