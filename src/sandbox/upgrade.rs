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

use std::ffi::{CStr, CString, OsStr, OsString};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::sync::OnceLock;

use libc::open_how;
use libseccomp::ScmpSyscall;
use log::{debug, error, warn};

use crate::access::fs::OpenOperation;
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

/// Whether an `io::Error` from resolving or opening a proxied target is a
/// benign, app-caused condition — the traced process is simply touching a
/// path that does not exist or that it is not allowed to open — rather
/// than a sandbox-side fault.  These are logged at `debug` instead of
/// `warn` / `error` so an app probing missing / forbidden paths cannot
/// spam the logs.
fn is_benign_target_errno(e: &std::io::Error) -> bool {
	matches!(
		e.raw_os_error(),
		Some(libc::ENOENT) | Some(libc::EPERM) | Some(libc::EACCES)
	)
}

/// `warn!` a proxied-target failure, but downgrade to `debug!` when the
/// underlying error is a benign app-caused errno (see
/// [`is_benign_target_errno`]).
macro_rules! warn_unless_benign {
	($e:expr, $($arg:tt)+) => {
		if is_benign_target_errno($e) {
			debug!($($arg)+);
		} else {
			warn!($($arg)+);
		}
	};
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

	/// The deepest tracked mount covering `sandbox_path` (the path itself
	/// or an ancestor), returned as its sandbox mount path, host path, and
	/// attributes.  `None` if no tracked mount covers it.
	fn covering_mount(&self, sandbox_path: &OsStr) -> Option<(OsString, CString, MountAttributes)> {
		self.current_mount_tree
			.lock()
			.expect("current_mount_tree lock poisoned")
			.find(sandbox_path, |_, _| true)
			.map(|(p, mi)| (p.to_owned(), mi.user.host_path.clone(), mi.user.attrs))
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

	/// If the target is based on a shadowed (aka. stale) dfd, i.e. its
	/// current `mnt_id` differs from the tracked mount covering its path,
	/// return that sandbox path (as a `CString`) and the fd's inode
	/// identity.  Returns `None` when it's not shadowed, the path is not
	/// covered by a tracked mount, or the fd cannot be inspected.
	fn is_fstarget_shadowed(&self, target: &FsTarget) -> Option<(CString, InodeId)> {
		if let OriginalHandle::Root = target.get_original_handle() {
			// root is never shadowed
			return None;
		}
		let dfd = target.dfd();
		self.is_dfd_shadowed(dfd)
	}

	// is_fstarget_shadowed but takes a ForeignFd directly
	fn is_dfd_shadowed(&self, dfd: &ForeignFd) -> Option<(CString, InodeId)> {
		let stx = dfd.statx(libc::STATX_MNT_ID | libc::STATX_INO).ok()?;
		if stx.stx_mask & libc::STATX_MNT_ID == 0 {
			let try_realpath = dfd.readlink().ok().unwrap_or_else(|| OsString::from("???"));
			debug!(
				"statx(AT_EMPTY_PATH) on fd {} (-> {:?}) did not return mount id",
				dfd.as_raw_fd(),
				try_realpath
			);
			// We can't determine if it's shadowed without mount id.
			return None;
		}
		let cur_mnt = stx.stx_mnt_id;
		let sandbox_path = dfd.readlink().ok()?;
		match self.expected_mnt_id(&sandbox_path) {
			Some(0) => {
				// We can't determine if it's shadowed without knowing the
				// covering mount's mount id.
				return None;
			}
			Some(exp) if exp == cur_mnt => return None,
			None => return None,
			Some(exp) => {
				debug!(
					"fd {} (-> {:?}) is shadowed: mnt_id {} != expected {}",
					dfd.as_raw_fd(),
					sandbox_path,
					cur_mnt,
					exp
				);
				let mut vec = sandbox_path.into_encoded_bytes();
				vec.push(0);
				let path_c = CString::from_vec_with_nul(vec).unwrap();
				Some((
					path_c,
					InodeId {
						dev_major: stx.stx_dev_major,
						dev_minor: stx.stx_dev_minor,
						ino: stx.stx_ino,
					},
				))
			}
		}
	}

	/// Called by [`RequestHandle::allow`].
	fn allow_request(
		&self,
		request: &AccessRequest,
		ctx: &mut RequestContext,
	) -> Result<(), AccessRequestError> {
		let Operation::FsOperation(fsop) = request.operation();
		let syscall = ctx.syscall();

		// Open may need to be proxied if it's based on a CWD and that CWD
		// is shadowed.  We proxy or upgrade the fd it even if the open
		// request is read-only, to ensure the child always gets a
		// non-shadowed fd.
		if let FsOperation::FsOpen(op) = fsop {
			debug!("Handling open request {:?}", request.operation());
			let Some((path_c, inode_id)) = self.is_fstarget_shadowed(&op.target) else {
				// Openat with a non-shadowed base will always give us a
				// non-shadowed fd, since each walk inwards will step into
				// mounts, and .. will step out then move to the topmost
				// parent mount.
				return ctx.send_continue();
			};
			let dfd = op.target.dfd();
			match op.target.get_original_handle() {
				OriginalHandle::Cwd => {
					// Need proxy (can't upgrade cwd)
					return self.proxy_open(op, ctx);
				}
				OriginalHandle::Fd(orig_fd) => {
					// Upgrade the base fd
					let can_upgrade =
						self.try_upgrade_fd(ctx, dfd, orig_fd, &path_c, Some(inode_id))?;
					if !can_upgrade {
						warn!("non-dir fd {} (-> {:?}) given to openat", orig_fd, path_c);
					}
					return ctx.send_continue();
				}
				OriginalHandle::Root => unreachable!("root is never shadowed"),
			}
		}

		// chdir/fchdir: preemptively ensure a covering mount before the
		// kernel resolves cwd (cwd can't be upgraded after the fact).
		if let FsOperation::FsChdir(target) = fsop {
			debug!("Handling chdir request {:?}", request.operation());
			return self.handle_chdir(target, ctx);
		}

		// modification f* operations may need to have their fd upgraded,
		// or if they operate on non-directories, proxied.
		if let Some(target) = modifying_fsop_fd_target(fsop) {
			debug!("Handling f* request {:?}", request.operation());
			return self.handle_modifying_f_ops(fsop, target, ctx);
		}

		// *at with one or more dirfd: upgrade the fds if they are shadowed.
		let fd_indices = syscalls_fs::dfd_arg_indices(syscall);
		if !fd_indices.is_empty() {
			debug!("Handling *at request {:?}", request.operation());
			return self.allow_at_dirfds(&fd_indices, ctx);
		}

		ctx.send_continue()
	}

	/// Attempt to upgrade fd_raw in the target process by re-opening the
	/// proxied absolute `path` on the current sandbox mount layout.  If
	/// the fd is not upgradable, return Ok(false).
	fn try_upgrade_fd(
		&self,
		ctx: &mut RequestContext,
		fd_opened: &ForeignFd,
		fd_raw: libc::c_int,
		path: &CStr,
		inode_id: Option<InodeId>,
	) -> Result<bool, AccessRequestError> {
		let is_o_path = app_fd_is_o_path(ctx.pid(), fd_raw).map_err(|_| todo!())?;
		let mut is_dir = false;
		if !is_o_path {
			is_dir = fd_opened
				.is_dir()
				.map_err(|_| todo!("Add AccessRequestError variant"))?;
		}
		let upgradable = is_o_path || is_dir;
		if !upgradable {
			return Ok(false);
		}

		let openhow = if is_o_path {
			build_path_open_how()
		} else {
			build_dir_open_how()
		};
		let m1fd = match self.m1_open_checked(path, &openhow, inode_id) {
			Some(fd) => fd,
			None => todo!(
				"m1_open_checked need to return a proper error, then this function need to return BindMountSandboxError::OpenInM1Failed. When caller finds this, it should log the error and send CONTINUE to the app."
			),
		};
		warn!("upgrading shadowed fd {} using {:?}", fd_raw, path);
		// todo: can you examine O_CLOEXEC via fdinfo?
		ctx.replace_fd(m1fd.as_raw_fd(), fd_raw, false)?;
		Ok(true)
	}

	/// `openat` / `openat2` / `open` / `creat`: re-open the abspath in m1
	/// with the requested flags and hand the fresh fd to the app.
	fn proxy_open(
		&self,
		op: &OpenOperation,
		ctx: &mut RequestContext,
	) -> Result<(), AccessRequestError> {
		let Some(params) = open_reopen_params(ctx)? else {
			debug_assert!(
				false,
				"open_reopen_params returned None for open syscall {:?}",
				ctx.syscall()
			);
			return ctx.send_continue();
		};
		let abspath = match op.target.realpath() {
			Ok(p) => p,
			Err(e) => {
				warn_unless_benign!(
					&e,
					"openat upgrade: cannot resolve abspath for {}: {} — continuing natively",
					op.target,
					e
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
				// TODO: m1_open_checked need to return a proper error, then print here.
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
	/// is no fd to swap), so a mount must sit *exactly at* the target -
	/// then a later attribute change reaches the existing cwd handle, and
	/// reconcile preserves that mount's identity rather than detaching it.
	fn handle_chdir(
		&self,
		chdir_target: &FsTarget,
		ctx: &mut RequestContext,
	) -> Result<(), AccessRequestError> {
		let abspath = match chdir_target.realpath() {
			Ok(p) => p,
			Err(e) => {
				warn_unless_benign!(
					&e,
					"chdir: cannot resolve abspath for {}: {}",
					chdir_target,
					e
				);
				return ctx.send_continue();
			}
		};
		let abspath_bytes = abspath.as_bytes();
		if abspath_bytes == b"/" {
			return ctx.send_continue();
		}
		let target_os = OsStr::from_bytes(abspath_bytes);
		// The deepest tracked mount covering the target (the target itself
		// or an ancestor).  No covering mount means the policy does not
		// grant this chdir at all, so there is nothing to preempt — CONTINUE
		// and let the syscall fail / be handled by the caller.
		let Some((cov_path, cov_host, cov_attrs)) = self.covering_mount(target_os) else {
			return ctx.send_continue();
		};
		// A mount already exists *exactly* at the target: cwd is pinned to
		// a tracked mount whose identity reconcile preserves, so there is
		// nothing to do.
		if cov_path.as_os_str() == target_os {
			return ctx.send_continue();
		}
		// Covered only by an ancestor: add a dummy mount *exactly* at the
		// target so a later attribute change can affect the existing cwd
		// handle (cwd can't be upgraded after the fact).  Inherit the
		// covering mount's attrs and host subtree so the cwd keeps seeing
		// the same files and is not over-restricted.  `cov_path` is a strict
		// ancestor here, so the relative suffix is a component-boundary slice
		// that already starts with `/` (non-root ancestor) or is the whole
		// abspath (root mount).
		let suffix: &[u8] = if cov_path.as_os_str() == OsStr::new("/") {
			abspath_bytes
		} else {
			&abspath_bytes[cov_path.as_os_str().as_bytes().len()..]
		};
		let host_path_bytes = join_under_mount(cov_host.as_bytes(), suffix);
		if let Some(host_path) = to_cstring(&host_path_bytes) {
			let mp = ManagedMountPoint {
				host_path,
				attrs: cov_attrs,
			};
			if let Err(e) = self.add_or_update_mount(target_os, mp) {
				warn!(
					"chdir: failed to add preemptive mount on {:?}: {}",
					abspath, e
				);
			} else {
				debug!(
					"chdir: added preemptive {} mount on {:?}",
					cov_attrs, abspath
				);
			}
		}
		ctx.send_continue()
	}

	/// For an *at request with a proper dfd, we have a chance to inspect
	/// if it is shadowed and upgrade it, regardless of whether the
	/// request is modifying or not.
	fn allow_at_dirfds(
		&self,
		dfd_indices: &[u8],
		ctx: &mut RequestContext,
	) -> Result<(), AccessRequestError> {
		// The two fds can be treated independently, if one fails to
		// upgrade, the other may still succeed.
		for &idx in dfd_indices {
			let raw = ctx.arg(idx as usize) as libc::c_int;
			if raw == libc::AT_FDCWD || raw < 0 {
				continue;
			}
			let dfd = match ctx.arg_to_fd(idx as usize) {
				Ok(f) => f,
				Err(e) => {
					warn!("allow_at_dirfds: cannot open app fd {}: {}", raw, e);
					continue;
				}
			};
			let Some((path_c, expected)) = self.is_dfd_shadowed(&dfd) else {
				continue;
			};
			match self.try_upgrade_fd(ctx, &dfd, raw, &path_c, Some(expected)) {
				Ok(true) => {}
				Ok(false) => {
					warn!(
						"allow_at_dirfds: expected *at request dfd {} (-> {:?}) to be a directory or O_PATH, but it is not",
						raw, path_c
					);
				}
				Err(e) => {
					error!(
						"allow_at_dirfds: try_upgrade_fd failed for fd {} (-> {:?}): {}",
						raw, path_c, e
					);
				}
			};
		}
		ctx.send_continue()
	}

	/// Handle a metadata modification operation whose target is an
	/// already-open, possibly O_PATH descriptor (`fchmod` / `fchown` /
	/// `fsetxattr` / `fremovexattr`).
	///
	/// If the fd is shadowed but it is upgradable, it is upgraded,
	/// otherwise the operation is proxied.
	///
	/// Unlike other metadata modifying operations, `ftruncate` needs an
	/// actually writable fd when the process calls it, and so if we got
	/// here, the fd already has the required permission, so there is no
	/// need to upgrade or proxy anything.
	fn handle_modifying_f_ops(
		&self,
		fsop: &FsOperation,
		target: &FsTarget,
		ctx: &mut RequestContext,
	) -> Result<(), AccessRequestError> {
		if matches!(fsop, FsOperation::FsTruncate(_)) {
			return ctx.send_continue();
		}

		let dfd = target.dfd();
		if let OriginalHandle::Root = target.get_original_handle() {
			// root is never shadowed
			return ctx.send_continue();
		}

		// Nothing to fix unless the held fd's mount is stale.
		let Some((path_c, inode_id)) = self.is_fstarget_shadowed(target) else {
			return ctx.send_continue();
		};

		if let OriginalHandle::Fd(dfd_raw) = target.get_original_handle() {
			match self.try_upgrade_fd(ctx, dfd, dfd_raw, &path_c, Some(inode_id)) {
				Ok(true) => {
					// Upgraded in place; CONTINUE so the op resolves through
					// the live layout.
					return ctx.send_continue();
				}
				Ok(false) => {
					// can't upgrade, proxy.
				}
				Err(e) => {
					error!("try_upgrade_fd failed for fd {}: {}", dfd_raw, e);
					// proxy.
				}
			}
		}
		// else if OriginalHandle::Cwd (but shadowed), also proxy

		let how = build_path_open_how();
		let m1fd = match self.m1_open_checked(&path_c, &how, Some(inode_id)) {
			Some(fd) => fd,
			None => {
				// todo: ...
				return ctx.send_continue();
			}
		};
		match proxy_modify(fsop, m1fd.as_raw_fd()) {
			Ok(()) => ctx.send_value(0),
			Err(errno) => ctx.send_error(-errno),
		}
	}
}

/// Join a covering mount's `host` path with a `suffix` — the part of the
/// sandbox abspath below the covering mount, always starting with `/` —
/// yielding the host path the covered sandbox location actually maps to.
/// One trailing slash is dropped from `host` first so a root host (`/`)
/// joins cleanly.
fn join_under_mount(host: &[u8], suffix: &[u8]) -> Vec<u8> {
	let host = host.strip_suffix(b"/").unwrap_or(host);
	let mut out = host.to_vec();
	out.extend_from_slice(suffix);
	if out.is_empty() {
		out.push(b'/');
	}
	out
}

/// Build an `open_how` for faithfully re-opening an `openat`-family
/// target in m1.  Resolution is confined to m1's root.
///
/// TODO: RESOLVE_NO_SYMLINKS is not faithfully honored yet.  We pass the
/// flag through to the m1 `openat2` below, but the `abspath` we open was
/// itself produced by `FsTarget::realpath()`, which resolves the path by
/// *following* symlinks.  So a path the app submitted with
/// RESOLVE_NO_SYMLINKS that contained a symlink component (which should
/// have failed with ELOOP in the original call) gets resolved here, and
/// re-opening the already-resolved abspath finds no symlinks left and
/// succeeds.  Reproducing the original semantics requires resolving the
/// abspath without following symlinks (and failing the same way) — left
/// as future work.
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

/// Determine whether the app fd `raw` of process `pid` was opened with
/// `O_PATH` via fdinfo
fn app_fd_is_o_path(pid: libc::pid_t, raw: libc::c_int) -> Result<bool, io::Error> {
	let path = format!("/proc/{}/fdinfo/{}", pid, raw);
	let content = std::fs::read_to_string(&path)?;
	for line in content.lines() {
		if let Some(rest) = line.strip_prefix("flags:")
			&& let Ok(flags) = i32::from_str_radix(rest.trim(), 8)
		{
			return Ok(flags & libc::O_PATH != 0);
		}
	}
	Ok(false)
}

/// If `fsop` is a single-operand modification operation whose target
/// refers directly to an already-open descriptor (an `f*` call or an
/// `*at` call with `AT_EMPTY_PATH`), return that target.
fn modifying_fsop_fd_target(fsop: &FsOperation) -> Option<&FsTarget> {
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
fn proxy_modify(fsop: &FsOperation, fd: libc::c_int) -> Result<(), libc::c_int> {
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

	/// Allow the request, transparently upgrading fds or proxying the
	/// operation if the traced process is operating on a fd or cwd
	/// shadowed by newer mounts.
	///
	/// If the request requires any additional mounts, the caller must have
	/// already added them.
	pub fn allow(mut self) -> Result<(), AccessRequestError> {
		self.sandbox.allow_request(&self.request, &mut self.req_ctx)
	}

	/// Deny the request, failing the syscall with `errno`.
	pub fn deny(mut self, errno: libc::c_int) -> Result<(), AccessRequestError> {
		self.req_ctx.send_error(-errno.abs())
	}
}
