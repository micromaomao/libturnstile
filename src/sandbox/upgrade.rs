//! This module contains per-request fd upgrade logic for the
//! `ManagedBindMountSandbox`.  The main goal of "fd upgrades" is to
//! transparently handle cases where a sandboxed application has a handle
//! to a file or directory opened, and a later policy update results in
//! that handle pointing to shadowed part of the mount tree.  Essentially
//! we use ADDFD to swap the opened handle for a new, non-shadowed one.
//! The entry point for all this logic is
//! [`ManagedBindMountSandbox::new_request_handle`].

use std::ffi::{CStr, CString, OsStr, OsString};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::sync::OnceLock;

use libc::open_how;
use libseccomp::ScmpSyscall;
use log::{debug, error, warn};

use crate::access::fs::OpenOperation;
use crate::errors::BindMountSandboxError;
use crate::fstree::FsTree;
use crate::{
	AccessRequestError, RequestContext,
	access::{
		AccessRequest, Operation,
		fs::{
			ChmodOperation, ChownOperation, FallocateOperation, ForeignFd, FsOperation, FsTarget,
			InodeId, LinkOperation, OriginalHandle, RemoveXattrOperation, RenameOperation,
			SetXattrOperation, TruncateOperation, UtimensOperation,
		},
	},
	syscalls::fs as syscalls_fs,
};
use crate::{ManagedTreeEntry, MountInternal};

use super::{ManagedBindMountSandbox, ManagedMountPoint, MountAttributes, ProcPidFd};

/// `RequestHandle` wraps an [`AccessRequest`] and [`RequestContext`]
/// returned from
/// [`TurnstileTracer::yield_request`](crate::tracer::TurnstileTracer::yield_request).
/// See [`ManagedBindMountSandbox::new_request_handle`].
pub struct RequestHandle<'s, 't> {
	sandbox: &'s ManagedBindMountSandbox,
	request: AccessRequest,
	req_ctx: RequestContext<'t>,
}

impl<'s, 't> RequestHandle<'s, 't> {
	/// The original [`AccessRequest`].
	pub fn request(&self) -> &AccessRequest {
		&self.request
	}

	/// The original [`RequestContext`].
	pub fn req_ctx(&self) -> &RequestContext<'t> {
		&self.req_ctx
	}

	/// Mutable reference to the original [`RequestContext`].
	pub fn req_ctx_mut(&mut self) -> &mut RequestContext<'t> {
		&mut self.req_ctx
	}

	pub fn into_original_request(self) -> (AccessRequest, RequestContext<'t>) {
		(self.request, self.req_ctx)
	}

	/// Assume the caller's intention is to allow the request.
	/// Transparently upgrade fds or proxy the requested operation in the
	/// sandbox namespace if necessary, then continues the syscall.
	///
	/// This does not actually grant any access on its own, the caller is
	/// expected to have updated the policy to allow the request.  If not,
	/// the syscall (proxied or not) will still fail.
	pub fn allow(mut self) -> Result<(), AccessRequestError> {
		self.sandbox.allow_request(&self.request, &mut self.req_ctx)
	}

	/// Deny the request, failing the syscall with `errno`.
	pub fn deny(mut self, errno: libc::c_int) -> Result<(), AccessRequestError> {
		self.req_ctx.send_error(-errno.abs())
	}
}

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
/// parameters needed to faithfully re-open the target in m1.
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

/// The fields of `/proc/<pid>/fdinfo/<raw>` the upgrade path needs.
struct FdInfo {
	/// `file->f_flags` (octal `flags:` line).  Faithfully reflects both
	/// `O_PATH` and `O_CLOEXEC`.
	flags: i32,
	/// Current file offset (`pos:` line).
	pos: i64,
}

/// Read the `flags:` and `pos:` fields of the app fd `raw` of process
/// `pid` from `/proc/<pid>/fdinfo/<raw>`.  Both lines are always present
/// (the kernel emits them for every fd type, including `O_PATH`).
fn read_fdinfo(pid: libc::pid_t, raw: libc::c_int) -> Result<FdInfo, io::Error> {
	let path = format!("/proc/{}/fdinfo/{}", pid, raw);
	let content = std::fs::read_to_string(&path)?;
	let mut flags = None;
	let mut pos = None;
	for line in content.lines() {
		if let Some(rest) = line.strip_prefix("flags:") {
			flags = i32::from_str_radix(rest.trim(), 8).ok();
		} else if let Some(rest) = line.strip_prefix("pos:") {
			pos = rest.trim().parse::<i64>().ok();
		}
	}
	match (flags, pos) {
		(Some(flags), Some(pos)) => Ok(FdInfo { flags, pos }),
		_ => Err(io::Error::new(
			io::ErrorKind::InvalidData,
			"no parseable `flags:` / `pos:` line in fdinfo",
		)),
	}
}

/// Why an [`ManagedBindMountSandbox::m1_open_checked`] reopen did not
/// yield a usable handle.
enum M1OpenError {
	/// The `openat2` in m1 itself failed; carries the errno so a proxy
	/// caller can reproduce the error the app would have seen natively.
	OpenFailed(libc::c_int),
	/// The open succeeded but the resulting inode did not match the
	/// expected identity after retries — a TOCTOU race where the path now
	/// resolves to a different file.
	IdentityMismatch,
}

/// Result from [`ManagedBindMountSandbox::try_upgrade_fd`]
enum UpgradeOutcome {
	Upgraded,
	NotUpgradable,
	UpgradeFailed,
	RequestGone,
}

impl ManagedBindMountSandbox {
	/// Wrap a request yielded by the
	/// [`TurnstileTracer`](crate::tracer::TurnstileTracer) into a
	/// [`RequestHandle`] tied to this sandbox.  Instead of using
	/// [`RequestContext::send_continue`] or
	/// [`RequestContext::send_error`] directly, using the methods from
	/// this returned handle to "allow" or "deny" the request, after
	/// inspecting it as usual with
	/// [`ManagedBindMountSandbox::check_covered`] and applying any
	/// necessary policy updates, will allow the sandbox a chance to
	/// transparently upgrade any shadowed fds or proxy the request in the
	/// namespace with re-resolved path if necessary, to ensure that an
	/// operation that was not allowed by a previous policy, but is now
	/// allowed under an updated policy will work even if the sandboxed
	/// application re-uses previously opened dir fds, or has a cwd that
	/// is entered before the policy update.
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
	/// the freshly-opened fd's `(dev, ino)` must equal it; otherwise the
	/// open is retried, and after two failures an [`M1OpenError`] is
	/// returned that distinguishes a genuine open failure (with its errno)
	/// from an identity mismatch, so the caller can pick an appropriate
	/// response.
	fn m1_open_checked(
		&self,
		path: &CStr,
		how: &open_how,
		expected: Option<InodeId>,
	) -> Result<ForeignFd, M1OpenError> {
		let mut attempts = 0u32;
		loop {
			match self.sandbox.open_in_sandbox(path, how) {
				Ok(fd) => match expected {
					None => return Ok(fd),
					Some(exp) => match fd.inode_id() {
						Ok(id) if id == exp => return Ok(fd),
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
								return Err(M1OpenError::IdentityMismatch);
							}
						}
						Err(e) => {
							attempts += 1;
							debug!("m1 reopen of {:?}: statx failed: {}", path, e);
							if attempts >= 2 {
								return Err(M1OpenError::IdentityMismatch);
							}
						}
					},
				},
				Err(e) => {
					let errno = match &e {
						BindMountSandboxError::OpenInM1Failed(errno) => *errno,
						_ => libc::EIO,
					};
					attempts += 1;
					debug!(
						"m1 reopen of {:?} failed: {}, attempt {}",
						path, e, attempts
					);
					if attempts >= 2 {
						return Err(M1OpenError::OpenFailed(errno));
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
	///
	/// TODO: this function is misleading - it returns the InodeId of the
	/// target's dfd, not the target file!! Probably should just remove / refactor.
	fn is_fstarget_shadowed(&self, target: &FsTarget) -> Option<(CString, InodeId)> {
		if let OriginalHandle::Root = target.get_original_handle() {
			// root is never shadowed
			return None;
		}
		let dfd = target.dfd();
		self.is_dfd_shadowed(dfd)
	}

	/// Like [`is_fstarget_shadowed`](Self::is_fstarget_shadowed) but takes
	/// the dfd directly.  Does a single `statx(STATX_MNT_ID | STATX_INO)`
	/// and compares the fd's current `mnt_id` against the tracked covering
	/// mount's.
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
					// Upgrade the base dirfd in place, then CONTINUE so the
					// kernel re-resolves the path through the now-current
					// dirfd.
					match self.try_upgrade_fd(ctx, dfd, orig_fd, &path_c, Some(inode_id))? {
						UpgradeOutcome::RequestGone => return Ok(()),
						// Upgraded, or couldn't upgrade (fail open): in both
						// cases let the kernel resolve the open.
						UpgradeOutcome::Upgraded | UpgradeOutcome::UpgradeFailed => {}
						UpgradeOutcome::NotUpgradable => {
							// A non-directory base fd; the kernel will report
							// ENOTDIR natively on CONTINUE.
							warn!("non-dir fd {} (-> {:?}) given to openat", orig_fd, path_c);
						}
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

		// A file opened on a noexec mount can't be mmapped executable.
		// If exec is granted later, before any mmap we need to upgrade
		// any fds in shadowed noexec mounts.
		if let FsOperation::FsMmap(op) = fsop {
			if op.need_exec
				&& let Some((path_c, inode_id)) = self.is_fstarget_shadowed(&op.target)
				&& let OriginalHandle::Fd(fd_raw) = op.target.get_original_handle()
			{
				debug!("Handling mmap(PROT_EXEC) request {:?}", request.operation());
				if let Err(e) = self.upgrade_regular_file_fd(ctx, fd_raw, &path_c, Some(inode_id)) {
					error!(
						"mmap(PROT_EXEC): failed to upgrade fd {} (-> {:?}): {} — continuing natively",
						fd_raw, path_c, e
					);
				}
			}
			return ctx.send_continue();
		}

		// execveat(fd, "", AT_EMPTY_PATH) also needs to be handled
		// specially because it may require newly gained exec permission
		// but it's not something we can proxy like for other *at with
		// empty path or f* ops.
		if let FsOperation::FsExec(op) = fsop
			&& op.target.is_empty_path()
			&& let Some((path_c, inode_id)) = self.is_fstarget_shadowed(&op.target)
			&& let OriginalHandle::Fd(fd_raw) = op.target.get_original_handle()
		{
			debug!(
				"Handling execveat(AT_EMPTY_PATH) request {:?}",
				request.operation()
			);
			if let Err(e) = self.upgrade_regular_file_fd(ctx, fd_raw, &path_c, Some(inode_id)) {
				error!(
					"execveat(AT_EMPTY_PATH): failed to upgrade fd {} (-> {:?}): {} — continuing natively",
					fd_raw, path_c, e
				);
			}
			return ctx.send_continue();
		}

		// modification f* operations may need to have their fd upgraded,
		// or if they operate on non-directories, proxied.
		if let Some(target) = modifying_fsop_fd_target(fsop) {
			debug!("Handling f* request {:?}", request.operation());
			return self.handle_modifying_f_ops(fsop, target, ctx);
		}

		// Check for unlink / rmdir / rename / link that will fail with
		// EBUSY or EXDEV only due to ephemeral mounts that are not
		// otherwise present in the policy.  In such cases, we can force a
		// reconcile first to make them succeed if the ephemeral mounts
		// are no longer necessary.
		match fsop {
			FsOperation::FsUnlink(op) => {
				// unlink doesn't work if the directory is not empty
				// anyway, so we don't care about any child mounts of the
				// target.
				self.try_remove_ephemeral_mounts_on(&op.target)
			}
			FsOperation::FsRename(RenameOperation { from, to, exchange }) => {
				self.try_remove_ephemeral_mounts_on_2(from, to, *exchange)
			}
			FsOperation::FsLink(LinkOperation { from, to, .. }) => {
				self.try_remove_ephemeral_mounts_on_2(from, to, false)
			}
			_ => {}
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
	/// the fd is a regular file, this returns
	/// [`UpgradeOutcome::NotUpgradable`] without doing anything.
	fn try_upgrade_fd(
		&self,
		ctx: &mut RequestContext,
		fd_opened: &ForeignFd,
		fd_raw: libc::c_int,
		path: &CStr,
		inode_id: Option<InodeId>,
	) -> Result<UpgradeOutcome, AccessRequestError> {
		let flags = match read_fdinfo(ctx.pid(), fd_raw) {
			Ok(v) => v.flags,
			Err(e) => {
				debug!(
					"try_upgrade_fd: cannot read fdinfo for fd {} (-> {:?}): {}",
					fd_raw, path, e
				);
				return Ok(UpgradeOutcome::UpgradeFailed);
			}
		};
		let is_o_path = flags & libc::O_PATH != 0;
		// Preserve the app fd's close-on-exec setting on the swapped fd.
		let cloexec = flags & libc::O_CLOEXEC != 0;
		let mut is_dir = false;
		if !is_o_path {
			is_dir = match fd_opened.is_dir() {
				Ok(v) => v,
				Err(e) => {
					debug!(
						"try_upgrade_fd: cannot statx fd {} (-> {:?}): {}",
						fd_raw, path, e
					);
					return Ok(UpgradeOutcome::UpgradeFailed);
				}
			};
		}
		if !is_o_path && !is_dir {
			// A regular file (or other non-swap-safe fd): swapping would
			// clobber its f_pos / open state, so leave it to the caller.
			return Ok(UpgradeOutcome::NotUpgradable);
		}

		let openhow = if is_o_path {
			build_path_open_how()
		} else {
			build_dir_open_how()
		};
		let m1fd = match self.m1_open_checked(path, &openhow, inode_id) {
			Ok(fd) => fd,
			Err(e) => {
				match e {
					M1OpenError::OpenFailed(errno) => debug!(
						"try_upgrade_fd: m1 reopen of {:?} for fd {} failed: errno {}",
						path, fd_raw, errno
					),
					M1OpenError::IdentityMismatch => debug!(
						"try_upgrade_fd: m1 reopen of {:?} for fd {} failed identity check",
						path, fd_raw
					),
				}
				return Ok(UpgradeOutcome::UpgradeFailed);
			}
		};
		warn!("upgrading shadowed fd {} using {:?}", fd_raw, path);
		if let Err(e) = ctx.replace_fd(m1fd.as_raw_fd(), fd_raw, cloexec) {
			if ctx.still_valid()? {
				return Err(e);
			}
			return Ok(UpgradeOutcome::RequestGone);
		}
		Ok(UpgradeOutcome::Upgraded)
	}

	/// Upgrades an fd, with support even for regular files, preserving
	/// the seek offset.  Some states on the fd are still lost, like
	/// flock().  An fd sharing a file description (struct file) with
	/// another fd will also have this link broken.  Used for exec and
	/// mmap where proxying is impossible.
	fn upgrade_regular_file_fd(
		&self,
		ctx: &mut RequestContext,
		fd_raw: libc::c_int,
		path: &CStr,
		inode_id: Option<InodeId>,
	) -> Result<(), io::Error> {
		let info = read_fdinfo(ctx.pid(), fd_raw)?;
		// Re-open the same file on the live layout with the app fd's
		// original access mode / status flags (O_PATH included, so an
		// exec-only O_PATH fd stays openable).  Whether the transient m1 fd
		// is O_CLOEXEC is irrelevant - the target fd's close-on-exec is set
		// on replace_fd below.
		let how = build_open_how(&ReopenParams {
			flags: (info.flags as u32) as u64,
			mode: 0,
			resolve: 0,
		});
		let m1fd = self
			.m1_open_checked(path, &how, inode_id)
			.map_err(|e| match e {
				M1OpenError::OpenFailed(errno) => io::Error::from_raw_os_error(errno),
				M1OpenError::IdentityMismatch => io::Error::from_raw_os_error(libc::ESTALE),
			})?;
		// ADDFD shares the struct file, but we opened a fresh one, so seek
		// it to the app fd's current offset to keep reads/writes consistent.
		if info.pos > 0 {
			let r =
				unsafe { libc::lseek(m1fd.as_raw_fd(), info.pos as libc::off_t, libc::SEEK_SET) };
			if r < 0 {
				return Err(io::Error::last_os_error());
			}
		}
		let cloexec = info.flags & libc::O_CLOEXEC != 0;
		ctx.replace_fd(m1fd.as_raw_fd(), fd_raw, cloexec)
			.map_err(io::Error::other)?;
		warn!(
			"upgraded shadowed regular-file fd {} using {:?}",
			fd_raw, path
		);
		Ok(())
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

		let creating = params.flags & libc::O_CREAT as u64 != 0;
		// Here we get an expected "identity reference" by opening the
		// file using the originally passed in target, which might be
		// relative to some other potentially moving fd.  This is used to
		// compare with the inode we actually get when opening using
		// absolute path later, and prevents us from somehow opening a
		// different file than the one the app intended.
		let expected = if creating {
			// ...but we can't do this for files which we will create as
			// part of the open.
			None
		} else {
			op.target
				.open_target()
				.ok()
				.and_then(|fd| fd.inode_id().ok())
		};

		let how = build_open_how(&params);
		let fd = match self.m1_open_checked(&abspath_c, &how, expected) {
			Ok(fd) => fd,
			Err(M1OpenError::OpenFailed(errno)) => {
				// The open failed in m1 too, either because the policy
				// did not actually allow the file to be opened with the
				// requested access despite the caller calling
				// allow_request, or because of some other reason.  In any
				// case, pass the error back to the app.
				return ctx.send_error(-errno);
			}
			Err(M1OpenError::IdentityMismatch) => {
				// Can probably retry here but will just return -ESTALE to
				// avoid complex logic.
				return ctx.send_error(-libc::ESTALE);
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
		let Some((cov_path, cov_host, cov_attrs)) = self.covering_mount(target_os) else {
			// No covering mount means the policy does not in fact grant
			// this chdir at all, even though it called allow_request.
			// Let's just do nothing.
			return ctx.send_continue();
		};
		// If we're already full permission, don't bother setting up
		// ephemeral mounts.  This is an optimization to avoid the cost of
		// creating lots of mount points under paths which the sandboxed
		// app has full access, at the expense of not being able to take
		// away access in arbitrarily fine-grained ways in the future.
		if !cov_attrs.readonly && !cov_attrs.noexec {
			return ctx.send_continue();
		}
		// A mount already exists at the target: in this case we don't
		// need to create any ephemeral mounts as we can always change the
		// attribute of this existing mount or move it after the fact if
		// we want to change permission on either this dir or any of its
		// parent.
		if cov_path.as_os_str() == target_os {
			// TODO: this is not technically correct - if we don't tie the
			// pid here with the mount, we may try to unmount it in the
			// future without realizing that it's supposed to eventually
			// be backing the cwd of a process.  Normally the umount would
			// fail due to EBUSY, but if by the time we try to unmount it,
			// the chdir has not been executed by the kernel yet, we will
			// race.
			return ctx.send_continue();
		}
		// Covered only by an ancestor: add an ephemeral mount at the
		// target to allow us maximum flexibility later to change the
		// attributes of, or move this cwd's mount around.  Inherit the
		// covering mount's attrs and host subtree so the cwd's view is
		// not changed.
		let suffix: &[u8] = if cov_path.as_os_str() == OsStr::new("/") {
			abspath_bytes
		} else {
			&abspath_bytes[cov_path.as_os_str().as_bytes().len()..]
		};
		let host_path_bytes = join_suffix_onto_abs_path(cov_host.as_bytes(), suffix);
		if let Some(host_path) = to_cstring(&host_path_bytes) {
			// Capture a pidfd to the thread issuing the chdir (cwd is
			// per-thread), then tie it together with the ephemeral mount
			// so a future reclaim of this mount does not race with the
			// chdir still executing.
			match ProcPidFd::from_tid(ctx.pid()) {
				Ok(pidfd) => {
					let mp = ManagedMountPoint {
						host_path,
						attrs: cov_attrs,
					};
					if let Err(e) =
						self.make_ephemeral_mount_for_cwd(target_os, mp, std::sync::Arc::new(pidfd))
					{
						warn!(
							"chdir: failed to add ephemeral mount on {:?}: {}",
							abspath, e
						);
					} else {
						debug!(
							"chdir: added ephemeral {} mount on {:?}",
							cov_attrs, abspath
						);
					}
				}
				Err(e) => {
					warn!(
						"chdir: cannot open pidfd for tid {} ({:?}): {} - skipping ephemeral mount",
						ctx.pid(),
						abspath,
						e
					);
				}
			}
		}
		ctx.send_continue()
	}

	/// Force a reconcile to remove no-longer-needed ephemeral mounts if
	/// the target sits on an ephemeral mount.
	fn try_remove_ephemeral_mounts_on(&self, target: &FsTarget) {
		let abspath = match target.realpath() {
			Ok(p) => p,
			Err(e) => {
				warn_unless_benign!(&e, "unlink: cannot resolve abspath for {}: {}", target, e);
				return;
			}
		};
		let (policy, mut pt, mut mt) = self.lock_trees();
		let on_ephemeral_mount = mt.get(&abspath).is_some() && policy.get(&abspath).is_none();
		if on_ephemeral_mount {
			debug!(
				"unlink target {:?} is an ephemeral mountpoint - forcing reconcile",
				abspath
			);
			self.reconcile(&mut pt, &mut mt, &policy, None);
		}
	}

	/// Force a reconcile to remove no-longer-needed ephemeral mounts if
	/// the two targets are on different live (ephemeral) mounts but the
	/// same policy mount, or if the source (or destination, in case of
	/// RENAME_EXCHANGE) contains mounts but only ephemeral mounts as
	/// their children.
	fn try_remove_ephemeral_mounts_on_2(&self, from: &FsTarget, to: &FsTarget, is_exchange: bool) {
		let from_path = match from.realpath() {
			Ok(p) => p,
			Err(e) => {
				warn_unless_benign!(
					&e,
					"rename/link: cannot resolve abspath for source {}: {}",
					from,
					e
				);
				return;
			}
		};
		let to_path = match to.realpath() {
			Ok(p) => p,
			Err(e) => {
				warn_unless_benign!(
					&e,
					"rename/link: cannot resolve abspath for destination {}: {}",
					to,
					e
				);
				return;
			}
		};
		let mut need_reconcile = false;
		let (policy, mut pt, mut mt) = self.lock_trees();
		let cur_from = mt.find(&from_path, |_, _| true).map(|(p, _)| p);
		let cur_to = mt.find(&to_path, |_, _| true).map(|(p, _)| p);
		if cur_from == cur_to {
			// then pol_from == pol_to is implied.  In this case we don't
			// need to reconcile to resolve EXDEV, but we still check if
			// we can get rid of EBUSY
			let (n_ephemeral, n_policy) =
				self.count_mount_kinds_under_path(&from_path, &policy, &mut mt);
			if n_policy > 0 {
				// it will fail anyway, don't bother.
				return;
			}
			if n_ephemeral > 0 {
				need_reconcile = true;
			}
			let (n_ephemeral, n_policy) =
				self.count_mount_kinds_under_path(&to_path, &policy, &mut mt);
			if n_policy > 0 || (!is_exchange && n_ephemeral > 0) {
				// it will fail anyway, don't bother.
				return;
			}
			if n_ephemeral > 0 {
				need_reconcile = true;
			}
			if !need_reconcile {
				return;
			}
		} else {
			let pol_from = policy.find(&from_path, |_, _| true).map(|(p, _)| p);
			let pol_to = policy.find(&to_path, |_, _| true).map(|(p, _)| p);
			if pol_from != pol_to {
				return;
			}
			need_reconcile = true;
		}
		if need_reconcile {
			debug!(
				"rename/link {:?} -> {:?} may fail due to ephemeral mounts - forcing reconcile",
				from_path, to_path
			);
			self.reconcile(&mut pt, &mut mt, &policy, None);
		}
	}

	fn count_mount_kinds_under_path(
		&self,
		path: &OsStr,
		policy: &FsTree<ManagedTreeEntry>,
		current_mt: &mut FsTree<MountInternal>,
	) -> (usize, usize) {
		let mut n_ephemeral = 0;
		let mut n_policy = 0;
		current_mt.walk_subtree_top_down(path, true, |path, _data| {
			if policy.get(path).is_none() {
				n_ephemeral += 1;
			} else {
				n_policy += 1;
			}
		});
		(n_ephemeral, n_policy)
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
			match self.try_upgrade_fd(ctx, &dfd, raw, &path_c, Some(expected))? {
				UpgradeOutcome::Upgraded | UpgradeOutcome::UpgradeFailed => {}
				UpgradeOutcome::RequestGone => return Ok(()),
				UpgradeOutcome::NotUpgradable => {
					warn!(
						"allow_at_dirfds: expected *at request dfd {} (-> {:?}) to be a directory or O_PATH, but it is not",
						raw, path_c
					);
				}
			}
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
	/// Unlike other metadata modifying operations, `ftruncate` and
	/// `fallocate` need an actually writable fd when the process calls
	/// them, and so if we got here, the fd already has the required
	/// permission, so there is no need to upgrade or proxy anything.
	fn handle_modifying_f_ops(
		&self,
		fsop: &FsOperation,
		target: &FsTarget,
		ctx: &mut RequestContext,
	) -> Result<(), AccessRequestError> {
		if matches!(
			fsop,
			FsOperation::FsTruncate(_) | FsOperation::FsFallocate(_)
		) {
			return ctx.send_continue();
		}

		// Nothing to fix unless the held fd's mount is stale.  (An f*
		// target always comes from an explicit fd, so it is never
		// Root/Cwd; the shadow check returns None for those anyway.)
		let Some((path_c, inode_id)) = self.is_fstarget_shadowed(target) else {
			return ctx.send_continue();
		};

		let dfd = target.dfd();
		if let OriginalHandle::Fd(dfd_raw) = target.get_original_handle() {
			match self.try_upgrade_fd(ctx, dfd, dfd_raw, &path_c, Some(inode_id))? {
				// Upgraded in place (including an O_PATH fd, which keeps
				// its native O_PATH semantics on the live mount): CONTINUE
				// so the op resolves through the live layout.
				UpgradeOutcome::Upgraded => return ctx.send_continue(),
				// Couldn't upgrade an upgradable fd: fail open rather than
				// proxy.  We must never proxy here without knowing the fd
				// is a regular file — a path-based proxy of an O_PATH fd
				// would turn a native EBADF into a spurious success.
				UpgradeOutcome::UpgradeFailed => return ctx.send_continue(),
				UpgradeOutcome::RequestGone => return Ok(()),
				// A confirmed regular file: fall through to the m1 proxy.
				UpgradeOutcome::NotUpgradable => {}
			}
		} else {
			// No explicit fd to swap (shouldn't happen for an f* target).
			return ctx.send_continue();
		}

		// Unupgradable (a regular file): a swap would clobber its
		// `f_pos`/open state, so perform the op in m1 against the live
		// layout and return its result directly.
		let how = build_path_open_how();
		let m1fd = match self.m1_open_checked(&path_c, &how, Some(inode_id)) {
			Ok(fd) => fd,
			// Reproduce the error the app would have seen; on an identity
			// race report ESTALE rather than acting on the wrong inode.
			Err(M1OpenError::OpenFailed(errno)) => return ctx.send_error(-errno),
			Err(M1OpenError::IdentityMismatch) => return ctx.send_error(-libc::ESTALE),
		};
		match proxy_modify(fsop, m1fd.as_raw_fd()) {
			Ok(()) => ctx.send_value(0),
			Err(errno) => ctx.send_error(-errno),
		}
	}
}

/// Produce the path `host`+`suffix`. `suffix` must have a leading `/`,
/// `host` can either have or not have a trailing `/` but must be an
/// absolute path.  Result will be an absolute path.
fn join_suffix_onto_abs_path(host: &[u8], suffix: &[u8]) -> Vec<u8> {
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
/// TODO: RESOLVE_NO_SYMLINKS is not faithfully honored yet.  We will pass
/// the flag through to the m1 `openat2`, but the `abspath` we open will
/// itself be produced by `FsTarget::realpath()`, which does not honor
/// RESOLVE_NO_SYMLINKS (because FsTarget currently does not track
/// resolve_no_symlinks, only no_follow).  So a path the app submitted
/// with RESOLVE_NO_SYMLINKS that contained a symlink component (which
/// should have failed with ELOOP in the original call) gets resolved
/// here, and re-opening the already-resolved abspath finds no symlinks
/// left and succeeds.  Reproducing the original semantics requires the
/// caller to resolve the original abspath without following symlinks, and
/// ELOOP if any are found.
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

/// If `fsop` is a single-operand modification operation whose target
/// refers directly to an already-open descriptor (an `f*` call or an
/// `*at` call with `AT_EMPTY_PATH`), return that target.
fn modifying_fsop_fd_target(fsop: &FsOperation) -> Option<&FsTarget> {
	let target = match fsop {
		FsOperation::FsChmod(ChmodOperation { target, .. })
		| FsOperation::FsChown(ChownOperation { target, .. })
		| FsOperation::FsTruncate(TruncateOperation { target, .. })
		| FsOperation::FsFallocate(FallocateOperation { target, .. })
		| FsOperation::FsUtimens(UtimensOperation { target, .. })
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
			FsOperation::FsUtimens(UtimensOperation { target, times }) => {
				// todo: symlink handling here is incorrect
				let flags = if target.no_follow() {
					libc::AT_SYMLINK_NOFOLLOW
				} else {
					0
				};
				libc::utimensat(libc::AT_FDCWD, p, times.as_ptr(), flags)
			}
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
