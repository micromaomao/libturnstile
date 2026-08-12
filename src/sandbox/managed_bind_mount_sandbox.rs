use std::{
	ffi::{CStr, CString, OsStr, OsString},
	io::{self, Read},
	mem,
	os::{
		fd::{AsRawFd, FromRawFd, OwnedFd},
		unix::{ffi::OsStrExt, ffi::OsStringExt},
	},
	sync::{Arc, Mutex, OnceLock},
};

use log::{debug, error, info, warn};

use crate::{
	BindMountSandboxError,
	access::fs::ForeignFd,
	fstree::FsTree,
	sandbox::{
		SandboxOptions,
		bind_mount_sandbox::BindMountSandbox,
		mount_attributes::MountAttributes,
		mount_obj::MountObj,
		placeholders::{
			PlaceholderDirData, PlaceholderFileData, PlaceholderSymlinkData,
			create_or_update_placeholder, join_host_suffix, placeholder_default_no_metadata,
			stat_host,
		},
		utils::{next_scratch_name, split_parent_leaf, umount_detach_fd, validate_sandbox_path},
	},
	utils::{ENABLE_LOG_IN_FORK, fork_wait},
};

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serialize")]
use crate::utils::{deserialize_cstring, serialize_cstring};

#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedMountPoint {
	#[cfg_attr(
		feature = "serialize",
		serde(
			serialize_with = "serialize_cstring",
			deserialize_with = "deserialize_cstring"
		)
	)]
	pub host_path: CString,
	pub attrs: MountAttributes,
}

/// Internal per-mount bookkeeping kept in `current_mount_tree`.  Wraps
/// the user-facing [`ManagedMountPoint`] with the kernel `mnt_id`
/// captured at mount-creation time, used as the staleness key when
/// deciding whether a held fd must be re-resolved through the current
/// mount layout.
#[derive(Debug, Clone)]
pub(crate) struct MountInternal {
	/// host_path + currently-applied attrs (the user-visible part).
	pub user: ManagedMountPoint,
	/// Kernel `mnt_id` captured at creation via `statx(STATX_MNT_ID)`
	/// from the m1 helper; 0 if the capture failed.
	pub mnt_id: u64,
	/// For ephemeral mounts created on a chdir request, this tracks the
	/// threads that resulted in the creation of this ephemeral mount.
	/// This is used to prevent us from removing such an ephemeral mount
	/// when the thread is still executing its `chdir`, which will result in its
	/// cwd not actually being on an ephemeral mount.
	pub cwd_of: Vec<Arc<ProcPidFd>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedTreeEntry {
	Placeholder(ManagedPlaceholder),
	BindMount(ManagedMountPoint),
}

#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serialize", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedPlaceholder {
	Dir(PlaceholderDirData),
	File(PlaceholderFileData),
	Symlink(PlaceholderSymlinkData),
}

/// An `O_PATH` handle to `/proc/<tid>` (a *thread*, not a thread group)
/// used to inspect a sandboxed thread's liveness, current working
/// directory, and current syscall.  Holding the procfs directory open is
/// reuse-safe: once the original task exits, the dentry is invalidated and
/// `openat` / `readlinkat` through this handle fail with `ENOENT` / `ESRCH`
/// even if the kernel later recycles the tid.
#[derive(Debug)]
pub(crate) struct ProcPidFd {
	tid: libc::pid_t,
	dirfd: OwnedFd,
}

impl ProcPidFd {
	/// Open `/proc/<tid>` (the per-thread procfs directory).
	pub(crate) fn from_tid(tid: libc::pid_t) -> io::Result<Self> {
		let path = format!("/proc/{}\0", tid);
		let fd = unsafe {
			libc::open(
				path.as_ptr() as *const libc::c_char,
				libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
			)
		};
		if fd < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(Self {
			tid,
			dirfd: unsafe { OwnedFd::from_raw_fd(fd) },
		})
	}

	pub(crate) fn tid(&self) -> libc::pid_t {
		self.tid
	}

	/// Open a file relative to `/proc/<tid>` (e.g. `status`, `cwd`,
	/// `syscall`) through the held directory handle.
	fn open_proc_file(&self, name: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
		let fd = unsafe { libc::openat(self.dirfd.as_raw_fd(), name.as_ptr(), flags) };
		if fd < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(unsafe { OwnedFd::from_raw_fd(fd) })
	}

	/// Whether the thread is still alive (not reaped / not a zombie).
	pub(crate) fn is_alive(&self) -> io::Result<bool> {
		match self.open_proc_file(c"status", libc::O_RDONLY | libc::O_CLOEXEC) {
			Ok(fd) => {
				let mut f = std::fs::File::from(fd);
				let mut s = String::new();
				f.read_to_string(&mut s)?;
				Ok(!s.contains("State:\tZ"))
			}
			Err(e) => match e.raw_os_error() {
				// Dentry invalidated: the task exited (and the tid may have
				// been recycled - this handle still refers to the old one).
				Some(libc::ENOENT) | Some(libc::ESRCH) => Ok(false),
				_ => Err(e),
			},
		}
	}

	/// Read the thread's current working directory (as a sandbox-namespace
	/// path) by `readlinkat`-ing `/proc/<tid>/cwd`.
	pub(crate) fn cwd(&self) -> io::Result<OsString> {
		let mut buf = vec![0u8; libc::PATH_MAX as usize];
		let ret = unsafe {
			libc::readlinkat(
				self.dirfd.as_raw_fd(),
				c"cwd".as_ptr(),
				buf.as_mut_ptr() as *mut libc::c_char,
				buf.len(),
			)
		};
		if ret < 0 {
			return Err(io::Error::last_os_error());
		}
		buf.truncate(ret as usize);
		Ok(OsString::from_vec(buf))
	}

	/// Determine whether the thread is currently executing a `chdir` /
	/// `fchdir` syscall using /proc/.../syscall.
	pub(crate) fn in_chdir_syscall(&self) -> Result<bool, io::Error> {
		let fd = self.open_proc_file(c"syscall", libc::O_RDONLY | libc::O_CLOEXEC)?;
		let mut f = std::fs::File::from(fd);
		let mut s = String::new();
		f.read_to_string(&mut s)?;
		let Some(first) = s.split_whitespace().next() else {
			return Ok(false);
		};
		match first.parse::<i64>() {
			Ok(nr) => Ok(chdir_syscall_nrs().contains(&nr)),
			// not a number
			Err(_) => Ok(false),
		}
	}
}

/// Debug-print an [`FsTree`], one node per line, indented by depth and
/// using [`FsTree::walk_top_down`].  Each line is `<path>: <Debug of
/// node>`, e.g.
///
/// ```text
/// /: ...
///   /usr: ...
///   /home: ...
///     /home/mao: ...
///   /proc: ...
/// ```
fn print_tree<T: std::fmt::Debug>(label: &str, tree: &FsTree<T>) {
	if !log::log_enabled!(log::Level::Debug) {
		return;
	}
	let mut out = format!("{}:", label);
	tree.walk_top_down(|path, node| {
		let depth = path
			.as_encoded_bytes()
			.split(|&b| b == b'/')
			.filter(|s| !s.is_empty())
			.count();
		out.push_str(&format!(
			"\n{}{}: {:?}",
			"  ".repeat(depth),
			path.to_string_lossy(),
			node
		));
	});
	debug!("{}", out);
}

/// Remove "useless" bind-mount entries from a *policy* tree in place: a
/// bind mount whose attributes match the nearest covering parent mount and
/// which exposes exactly the host subtree that parent already exposes
/// (`host_path == parent_host + suffix`) is redundant, since the parent
/// bind already makes that subtree visible with the same permissions.
///
/// This is applied to the saved policy by the policy-mutating entry points
/// (`add_/remove_/update_*`) so stray redundant mounts (e.g. a per-request
/// leaf that a broader grant later subsumed) don't accumulate.  It is
/// deliberately *not* applied on the `chdir` path, whose temporary cwd
/// mount is redundant by this very definition yet must be materialised.
fn prune_useless_mounts(policy: &mut FsTree<ManagedTreeEntry>) {
	let mut to_remove: Vec<OsString> = Vec::new();
	policy.fold_top_down_from(
		|path, entry, covering: Option<(Vec<u8>, Vec<u8>, MountAttributes)>| match entry {
			ManagedTreeEntry::Placeholder(_) => covering,
			ManagedTreeEntry::BindMount(mp) => {
				if let Some((ref par_sb, ref par_host, par_attrs)) = covering {
					let expected_host = join_host_suffix(par_host, par_sb, path.as_encoded_bytes());
					if mp.attrs == par_attrs && mp.host_path.to_bytes() == expected_host.as_slice()
					{
						// Redundant: drop it, but keep the same covering mount
						// for descendants (it renders identically).
						to_remove.push(path.to_owned());
						return covering;
					}
				}
				Some((
					path.as_encoded_bytes().to_vec(),
					mp.host_path.to_bytes().to_vec(),
					mp.attrs,
				))
			}
		},
		None,
		OsStr::new("/"),
	);
	for p in to_remove {
		policy.remove(&p);
	}
}

/// Syscall numbers for `chdir` / `fchdir`, resolved once for the native
/// architecture.  Used by [`ProcPidFd::in_chdir_syscall`] to tell whether
/// a thread is *currently* executing a directory-change syscall.
fn chdir_syscall_nrs() -> &'static [i64] {
	static ONCE: OnceLock<Vec<i64>> = OnceLock::new();
	ONCE.get_or_init(|| {
		let mut v = Vec::new();
		for name in ["chdir", "fchdir"] {
			if let Ok(nr) = libseccomp::ScmpSyscall::from_name(name) {
				v.push(i32::from(nr) as i64);
			}
		}
		v
	})
}

/// Pick out the reconcile error (if any) that relates to `path`,
/// discarding errors on unrelated paths.
fn pick_error_for_path(
	errors: Vec<(OsString, BindMountSandboxError)>,
	path: &OsStr,
) -> Result<(), BindMountSandboxError> {
	for (p, e) in errors {
		if p.as_os_str() == path {
			return Err(e);
		}
	}
	Ok(())
}

fn check_path_no_nul(path: &OsStr) -> Result<(), BindMountSandboxError> {
	if path.as_encoded_bytes().contains(&0) {
		return Err(BindMountSandboxError::InvalidSandboxPath(
			"path contains NUL byte",
			CString::from_vec_with_nul(format!("{:?}", path).into_bytes())
				.expect("debug format should not contain NUL bytes"),
		));
	}
	Ok(())
}

/// A bind-mount based sandbox that automatically mount and unmounts based
/// on a desired state.
#[derive(Debug)]
pub struct ManagedBindMountSandbox {
	pub(super) sandbox: BindMountSandbox,
	/// The desired policy, which may not match the actual current mount
	/// tree, if for example some mount or unmount operations failed
	/// during reconciliation.
	current_policy: Mutex<FsTree<ManagedTreeEntry>>,
	/// The current, live placeholder tree.
	current_placeholder_tree: Mutex<FsTree<ManagedPlaceholder>>,
	/// The current, live mount tree.  This is only updated when the
	/// corresponding mount or unmount operation succeeds.
	pub(super) current_mount_tree: Mutex<FsTree<MountInternal>>,
}

impl ManagedBindMountSandbox {
	pub fn new(options: SandboxOptions) -> Result<Self, BindMountSandboxError> {
		Ok(Self {
			sandbox: BindMountSandbox::new(options)?,
			current_policy: Mutex::new(FsTree::new()),
			current_placeholder_tree: Mutex::new(FsTree::new()),
			current_mount_tree: Mutex::new(FsTree::new()),
		})
	}

	/// Update a single entry (placeholder or mount) in the policy, then
	/// run reconciliation.
	///
	/// Reconciliation may touch other paths if the policy does not fully
	/// match the current mount tree, but only an error relating to `path`
	/// itself is surfaced to the caller; failures on unrelated paths are
	/// logged by `reconcile` but do not fail this call.
	pub fn add_or_update_entry(
		&self,
		path: &OsStr,
		entry: ManagedTreeEntry,
	) -> Result<(), BindMountSandboxError> {
		debug!("add_or_update_entry: path={:?}, entry={:?}", path, entry);
		check_path_no_nul(path)?;
		let (mut policy, mut pt, mut mt) = self.lock_trees();
		policy.insert(path, entry);
		prune_useless_mounts(&mut policy);
		let errors = self.reconcile(&mut pt, &mut mt, &policy, None);
		pick_error_for_path(errors, path)
	}

	/// Create an ephemeral mount at `target` with attribute `mp` to back
	/// the thread `pidfd`'s cwd, without persisting it to the policy.
	pub(super) fn make_ephemeral_mount_for_cwd(
		&self,
		target: &OsStr,
		mp: ManagedMountPoint,
		pidfd: Arc<ProcPidFd>,
	) -> Result<(), BindMountSandboxError> {
		check_path_no_nul(target)?;
		let (policy, mut pt, mut mt) = self.lock_trees();
		let errors = self.reconcile(
			&mut pt,
			&mut mt,
			&policy,
			Some((target.to_owned(), mp, pidfd)),
		);
		pick_error_for_path(errors, target)
	}

	/// A convenience wrapper for
	/// [`add_or_update_entry`](Self::add_or_update_entry) with a
	/// [`ManagedMountPoint`] argument.
	pub fn add_or_update_mount(
		&self,
		path: &OsStr,
		mp: ManagedMountPoint,
	) -> Result<(), BindMountSandboxError> {
		debug!("add_or_update_mount: path={:?}, mp={:?}", path, mp);
		self.add_or_update_entry(path, ManagedTreeEntry::BindMount(mp))
	}

	/// A convenience wrapper for
	/// [`add_or_update_entry`](Self::add_or_update_entry) with a
	/// [`ManagedPlaceholder`] argument.
	pub fn add_or_update_placeholder(
		&self,
		path: &OsStr,
		ph: ManagedPlaceholder,
	) -> Result<(), BindMountSandboxError> {
		debug!("add_or_update_placeholder: path={:?}, ph={:?}", path, ph);
		self.add_or_update_entry(path, ManagedTreeEntry::Placeholder(ph))
	}

	/// Remove either the placeholder or mount entry at the given path
	/// from the policy if it exists in the policy, then run
	/// reconciliation.  Reconciliation may touch other paths, but only
	/// failures relating to `path` itself are surfaced to the caller.
	pub fn remove_entry(&self, path: &OsStr) -> Result<(), BindMountSandboxError> {
		check_path_no_nul(path)?;
		let (mut policy, mut pt, mut mt) = self.lock_trees();
		policy.remove(path);
		prune_useless_mounts(&mut policy);
		let errors = self.reconcile(&mut pt, &mut mt, &policy, None);
		pick_error_for_path(errors, path)
	}

	/// Replace the policy with the given tree, then run reconciliation.
	/// Returns a list of errors.
	pub fn update_from_tree(
		&self,
		desired_tree: &FsTree<ManagedTreeEntry>,
	) -> Vec<(OsString, BindMountSandboxError)> {
		let (mut policy, mut pt, mut mt) = self.lock_trees();
		*policy = desired_tree.clone();
		prune_useless_mounts(&mut policy);
		self.reconcile(&mut pt, &mut mt, &policy, None)
	}

	/// Convenience wrapper for
	/// [`update_from_tree`](Self::update_from_tree) that takes a list of
	/// (path, entry) pairs instead of a tree.
	pub fn update_from_list<'a>(
		&self,
		desired_entries: impl IntoIterator<Item = (&'a OsStr, ManagedTreeEntry)>,
	) -> Vec<(OsString, BindMountSandboxError)> {
		let mut tree = FsTree::new();
		let mut errors = Vec::new();
		for (path, entry) in desired_entries {
			if let Err(e) = check_path_no_nul(path) {
				errors.push((path.to_owned(), e));
			} else {
				tree.insert(path, entry);
			}
		}
		errors.extend(self.update_from_tree(&tree).into_iter());
		errors
	}

	pub(super) fn lock_trees(
		&self,
	) -> (
		std::sync::MutexGuard<'_, FsTree<ManagedTreeEntry>>,
		std::sync::MutexGuard<'_, FsTree<ManagedPlaceholder>>,
		std::sync::MutexGuard<'_, FsTree<MountInternal>>,
	) {
		// Always acquire in the same order to avoid deadlocks.
		let policy = self
			.current_policy
			.lock()
			.expect("current_policy lock poisoned");
		let pt = self
			.current_placeholder_tree
			.lock()
			.expect("current_placeholder_tree lock poisoned");
		let mt = self
			.current_mount_tree
			.lock()
			.expect("current_mount_tree lock poisoned");
		(policy, pt, mt)
	}

	/// Bind-mount `host_path` at `ns_path` while "carrying over" any
	/// existing direct sub-mounts that the new bind would otherwise
	/// shadow.
	///
	/// `child_ns_paths` lists the immediate sub-mounts of `ns_path`.
	///
	/// Roughly, this function does:
	///
	/// - (in m0) `open_tree` the host source.
	/// - (in m1) open an `O_PATH` fd to every child.
	/// - (in m1) `move_mount` the source onto `ns_path` (the children are
	///   now shadowed).
	/// - (in m1) `move_mount` each child back onto its own path resolved
	///   inside the new bind mount.
	///
	/// A child whose mountpoint dentry is absent from the new parent's
	/// host fs cannot be moved back, and so will be unmounted.
	///
	/// With no children this is exactly a plain bind mount.
	pub(super) fn mount_covering(
		&self,
		host_path: &CStr,
		ns_path: &CStr,
		attrs: MountAttributes,
		child_ns_paths: &[CString],
	) -> Result<(), BindMountSandboxError> {
		if child_ns_paths.is_empty() {
			return self
				.sandbox
				.mount_host_into_sandbox_impl(host_path, ns_path, attrs, false, false);
		}
		validate_sandbox_path(ns_path)?;

		let mut o_path_openhow: libc::open_how = unsafe { mem::zeroed() };
		o_path_openhow.flags = (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
		o_path_openhow.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_IN_ROOT;
		if log::log_enabled!(log::Level::Debug) {
			let ns_path_open = self
				.sandbox
				.open_in_sandbox(ns_path, &o_path_openhow)
				.unwrap();
			let mnt_id = ns_path_open.mnt_id().unwrap();
			debug!(
				"Mounting {:?} over {:?} (current mnt_id = {}) with {} children",
				host_path,
				ns_path,
				mnt_id,
				child_ns_paths.len()
			);
			for c in child_ns_paths {
				let c_open = self.sandbox.open_in_sandbox(c, &o_path_openhow).unwrap();
				let c_mnt_id = c_open.mnt_id().unwrap();
				debug!("  will move child {:?} with mnt_id = {}", c, c_mnt_id)
			}
		}

		let host_fd = self.sandbox.host_to_m0(host_path, false)?;

		// Pre-allocate the fd buffer before we fork so the forked child
		// does not allocate.
		let mut child_fds: Vec<libc::c_int> = vec![-1; child_ns_paths.len()];
		let child_fds_slice = child_fds.as_mut_slice();
		let n_children = child_ns_paths.len();

		let nsenter_fn_m0 = unsafe { self.sandbox.namespaces.nsenter_fn(true, true, false, false) };
		let nsenter_fn_m1 = unsafe {
			self.sandbox
				.namespaces
				.nsenter_fn(false, false, true, false)
		};
		let host_fd_raw = host_fd.as_raw_fd();
		let fork_res = unsafe {
			fork_wait(move || {
				if let Err(e) = nsenter_fn_m0() {
					return e.raw_os_error().unwrap_or(libc::EIO);
				}
				let source_tree = match MountObj::new_bind(host_fd_raw, c"", attrs, false) {
					Ok(tree) => tree,
					Err(e) => return e.raw_os_error().unwrap_or(libc::EIO),
				};
				if let Err(e) = nsenter_fn_m1() {
					return e.raw_os_error().unwrap_or(libc::EIO);
				}
				// Open every child while still reachable.
				let mut child_openhow: libc::open_how = mem::zeroed();
				child_openhow.flags = (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
				child_openhow.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_IN_ROOT;
				for i in 0..n_children {
					let fd = libc::syscall(
						libc::SYS_openat2,
						libc::AT_FDCWD,
						child_ns_paths[i].as_ptr(),
						&child_openhow as *const _,
						std::mem::size_of::<libc::open_how>(),
					) as libc::c_int;
					if fd < 0 {
						let err = libc::__errno_location().read();
						if ENABLE_LOG_IN_FORK {
							error!(
								"Failed to open child {:?} for move_mount: errno {}",
								child_ns_paths[i], err
							);
						}
					}
					// A child that can't be opened (already gone) is just
					// skipped; -1 stays in the slot.
					child_fds_slice[i] = fd;
				}
				// Bind the parent over ns_path (shadows the children).
				if let Err(e) = source_tree.mount(libc::AT_FDCWD, ns_path, false) {
					if ENABLE_LOG_IN_FORK {
						error!(
							"Failed to mount covering {:?} to {:?} with {}: {}",
							host_path, ns_path, attrs, e
						);
					}
					for &mut fd in child_fds_slice {
						if fd >= 0 {
							libc::close(fd);
						}
					}
					return e.raw_os_error().unwrap_or(libc::EIO);
				}
				// Move each child back onto its path inside the new bind
				// mount.  If the mountpoint dentry is missing in the new
				// parent the child can't be moved back, so lazily detach
				// it (MNT_DETACH) rather than leaving it shadowed; we
				// don't fail the whole op.
				for i in 0..n_children {
					let fd = child_fds_slice[i];
					if fd < 0 {
						continue;
					}
					let res = libc::syscall(
						libc::SYS_move_mount,
						fd,
						c"".as_ptr(),
						libc::AT_FDCWD,
						child_ns_paths[i].as_ptr(),
						libc::MOVE_MOUNT_F_EMPTY_PATH,
					);
					if res != 0 {
						let err = libc::__errno_location().read();
						if ENABLE_LOG_IN_FORK {
							error!("move_mount(child back) failed: errno {}", err);
						}
						if let Err(e) = umount_detach_fd(fd) {
							if ENABLE_LOG_IN_FORK {
								error!("umount_detach_fd failed: {}", e);
							}
						}
					}
					libc::close(fd);
				}
				0
			})
		}
		.map_err(BindMountSandboxError::ForkError)?;
		if fork_res != 0 {
			error!(
				"Failed to mount (covering) {:?} to {:?} with {}: errno {}",
				host_path, ns_path, attrs, fork_res
			);
			return Err(BindMountSandboxError::MountFailed(fork_res));
		}
		info!(
			"Mount bind (covering {} children) {:?} {:?} {}",
			n_children, host_path, ns_path, attrs
		);
		if log::log_enabled!(log::Level::Debug) {
			for c in child_ns_paths {
				let c_open = self.sandbox.open_in_sandbox(c, &o_path_openhow).unwrap();
				let c_mnt_id = c_open.mnt_id().unwrap();
				debug!("  moved child {:?} now with mnt_id = {}", c, c_mnt_id)
			}
		}
		Ok(())
	}

	/// Unmount `ns_path` while preserving its sub-mounts: park every
	/// direct sub-mount under `ns_path` to the hidden scratch tmpfs,
	/// attempt a non-detach `umount2(ns_path)`, then restore the parked
	/// sub-mounts onto their original paths.  Returns `Ok(true)` if the
	/// parent mount was successfully unmounted, or `Ok(false)` if it was
	/// kept because the app still holds it (i.e. the umount returned
	/// `EBUSY`).  In both cases the children should be kept intact (and
	/// thus any app fds / cwd resolving through them remain valid).
	pub(super) fn unmount_covering(
		&self,
		ns_path: &CStr,
		child_ns_paths: &[CString],
	) -> Result<bool, BindMountSandboxError> {
		validate_sandbox_path(ns_path)?;
		// Park each direct child out of the way so it can't pin the
		// parent; each gets a unique scratch directory.
		let mut parked: Vec<(CString, &CStr)> = Vec::with_capacity(child_ns_paths.len());
		for child in child_ns_paths {
			let name = next_scratch_name();
			if let Err(e) = self.sandbox.park_to_scratch(child, &name) {
				// Best-effort: restore anything already parked before
				// propagating the failure.
				for (name, dest) in &parked {
					let _ = self.sandbox.restore_from_scratch(name, dest);
				}
				return Err(e);
			}
			parked.push((name, child.as_c_str()));
		}
		// Attempt a non-detach unmount.  With every child parked, only the
		// app's own references on `ns_path` can still pin it.
		let unmounted = match self.sandbox.unmount(ns_path, false) {
			Ok(()) => true,
			Err(BindMountSandboxError::UnmountFailed(e)) if e == libc::EBUSY => false,
			Err(e) => {
				for (name, dest) in &parked {
					let _ = self.sandbox.restore_from_scratch(name, dest);
				}
				return Err(e);
			}
		};
		// Restore each parked child onto its original path: on the
		// revealed placeholder layer when unmounted, or under the kept
		// mount on EBUSY.
		for (name, dest) in &parked {
			self.sandbox.restore_from_scratch(name, dest)?;
		}
		Ok(unmounted)
	}

	/// Reconcile current state with `desired_entries`.  Caller locks the
	/// two internal states.
	///
	/// Steps:
	///   1. Build the desired placeholder tree from `desired_entries`,
	///      including ancestor directories.  For each bind-mount entry,
	///      synthesize a default placeholder (file or dir, based on the
	///      host stat) at the mount point if one isn't already specified
	///      by the user.
	///   2. Build the desired mount tree.
	///   3. Diff current_placeholder_tree -> desired_placeholder_tree
	///      and create/update placeholders (ignoring removals).
	///   4. Diff current_mount_tree -> desired_mount_tree and
	///      apply unmount / mount / set_mount_attr accordingly.
	///   5. Diff current_placeholder_tree -> desired_placeholder_tree
	///      again and remove now-unused placeholders (ignoring adds).
	///
	/// Reconciliation is best-effort and does not stop at the first
	/// failure: an error applying one path is recorded (annotated by the
	/// sandbox path it relates to) and the remaining pending
	/// modifications are still attempted.  The accumulated errors are
	/// returned to the caller, which decides which ones are relevant.
	pub(super) fn reconcile(
		&self,
		current_pt: &mut FsTree<ManagedPlaceholder>,
		current_mt: &mut FsTree<MountInternal>,
		desired_entries: &FsTree<ManagedTreeEntry>,
		chdir_mount: Option<(OsString, ManagedMountPoint, Arc<ProcPidFd>)>,
	) -> Vec<(OsString, BindMountSandboxError)> {
		let (desired_pt, mut desired_mt, mut errors) = self.build_desired_trees(desired_entries);
		if let Some((ref path, ref mp, _)) = chdir_mount {
			// Force-add the transient cwd mount, bypassing the useless-mount
			// merge in `build_desired_trees`: a chdir mount mirrors its
			// covering parent (so it *is* "useless" by that test) yet must be
			// materialised so a later attribute change can reach the pinned
			// cwd.  It lives under an existing covering mount, so the
			// mountpoint dentry comes from that mount's host fs - no extra
			// placeholder is needed.
			desired_mt.insert(path.as_os_str(), mp.clone());
		}
		print_tree("Current placeholder tree", current_pt);
		print_tree("Desired placeholder tree", &desired_pt);
		print_tree("Current mount tree", current_mt);
		print_tree("Desired mount tree", &desired_mt);

		let mut new_pt = current_pt.clone();
		let mut new_mt = current_mt.clone();

		// Phase 1: create / update placeholders top-down.
		current_pt.diff(
			&desired_pt,
			|sandbox_path, diff| {
				let ns_path =
					CString::new(sandbox_path.as_encoded_bytes()).expect("checked for NUL byte");
				match diff {
					crate::fstree::DiffTree::Added(new) => {
						if let Err(e) = self.apply_placeholder(&ns_path, new) {
							errors.push((sandbox_path.to_owned(), e));
							return;
						}
						new_pt.insert(sandbox_path, new.clone());
					}
					crate::fstree::DiffTree::Updated(_, new) => {
						if let Err(e) = self.apply_placeholder(&ns_path, new) {
							errors.push((sandbox_path.to_owned(), e));
							return;
						}
						*new_pt.get_mut(sandbox_path).expect("must exist") = new.clone();
					}
					crate::fstree::DiffTree::Removed(_) => {}
				}
			},
			|_, _, _| false,
			false,
		);

		// Phase 2: mounts diff.
		current_mt.diff(
			&desired_mt,
			|sandbox_path, diff| {
				let ns_path =
					CString::new(sandbox_path.as_encoded_bytes()).expect("checked for NUL byte");
				match diff {
					crate::fstree::DiffTree::Removed(old) => {
						if let Some(new) = desired_mt.get(sandbox_path)
							&& new.host_path != old.user.host_path
						{
							// Don't bother with keeping the mount, we
							// have been explicitly asked to change this
							// mount to point to something else, so just
							// MNT_DETACH
							if let Err(e) = self.sandbox.unmount(&ns_path, true) {
								errors.push((sandbox_path.to_owned(), e));
								return;
							}
							new_mt.remove(sandbox_path);
							return;
						}
						// A mount that might back a live thread's cwd
						// (notably an ephemeral `chdir` mount) either
						// right now or after the completion of a parallel
						// chdir must not be unmounted yet.
						if !old.cwd_of.is_empty() {
							let survivors = self.retained_cwd_holders(&old.cwd_of, sandbox_path);
							let entry = new_mt.get_mut(sandbox_path).expect("must exist");
							if !survivors.is_empty() {
								entry.cwd_of = survivors;
								return;
							}
							entry.cwd_of.clear();
						}
						// discover the direct (topmost) sub-mounts
						// still present under this path in the live tree
						// and hand them to the unmount routine, which
						// parks them out of the way, does a non-detach
						// umount, then restores them.
						let mut children: Vec<CString> = Vec::new();
						new_mt.walk_subtree_top_down(sandbox_path, true, |child_path, _| {
							if let Ok(c) = CString::new(child_path.as_encoded_bytes()) {
								children.push(c);
							}
						});
						match self.unmount_covering(&ns_path, &children) {
							Ok(true) => {
								new_mt.remove(sandbox_path);
							}
							Ok(false) => {
								// The app itself still holds this path.
								// Keep it but lock it down to the new
								// covering attrs; a later reconcile will
								// retry the removal again.
								let covering = self.covering_attrs(&desired_mt, sandbox_path);
								if covering != old.user.attrs {
									if let Err(e) = self.sandbox.set_mount_attr(
										&ns_path,
										covering,
										old.user.attrs,
									) {
										errors.push((sandbox_path.to_owned(), e));
										return;
									}
								}
								let entry = new_mt.get_mut(sandbox_path).expect("must exist");
								entry.user.attrs = covering;
							}
							Err(e) => {
								errors.push((sandbox_path.to_owned(), e));
								return;
							}
						}
					}
					crate::fstree::DiffTree::Added(new) => {
						// discover the immediate sub-mounts this new
						// bind would shadow (topmost mounts strictly under
						// the path in the live tree) and re-expose them.
						let mut children: Vec<CString> = Vec::new();
						new_mt.walk_subtree_top_down(sandbox_path, true, |child_path, _| {
							if let Ok(c) = CString::new(child_path.as_encoded_bytes()) {
								children.push(c);
							}
						});
						if let Err(e) =
							self.mount_covering(&new.host_path, &ns_path, new.attrs, &children)
						{
							errors.push((sandbox_path.to_owned(), e));
							return;
						}
						let mnt_id = self.capture_mnt_id(&ns_path);
						new_mt.insert(
							sandbox_path,
							MountInternal {
								user: (*new).clone(),
								mnt_id,
								cwd_of: Vec::new(),
							},
						);
					}
					crate::fstree::DiffTree::Updated(old, new) => {
						assert_eq!(old.user.host_path, new.host_path);
						if old.user.attrs != new.attrs {
							if let Err(e) =
								self.sandbox
									.set_mount_attr(&ns_path, new.attrs, old.user.attrs)
							{
								errors.push((sandbox_path.to_owned(), e));
								return;
							}
							let entry = new_mt.get_mut(sandbox_path).expect("must exist");
							entry.user = (*new).clone();
						}
					}
				}
			},
			|_, old, new| old.user.host_path != new.host_path,
			false,
		);

		// Tag the (now-materialised) cwd mount with its holding thread so a
		// later reconcile can tell it still backs a live cwd.  Covers both the
		// freshly-`Added` case and a repeat/concurrent chdir to a target that
		// already had a mount (which produces no diff).
		if let Some((path, _, pidfd)) = chdir_mount {
			if let Some(entry) = new_mt.get_mut(path.as_os_str()) {
				if !entry.cwd_of.iter().any(|p| p.tid() == pidfd.tid()) {
					entry.cwd_of.push(pidfd);
				}
			}
		}

		// Phase 3: remove placeholders no longer desired (bottom-up).
		current_pt.diff(
			&desired_pt,
			|sandbox_path, diff| {
				if matches!(diff, crate::fstree::DiffTree::Removed(_)) {
					let ns_path = CString::new(sandbox_path.as_encoded_bytes())
						.expect("checked for NUL byte");
					if ns_path.as_c_str() == c"/" {
						return;
					}
					if let Err(e) = self.sandbox.remove_placeholder(&ns_path) {
						errors.push((sandbox_path.to_owned(), e));
						return;
					}
					new_pt.remove(sandbox_path);
				}
			},
			|_, _, _| false,
			false,
		);

		*current_pt = new_pt;
		*current_mt = new_mt;
		for (path, err) in &errors {
			warn!("reconcile: error applying {:?}: {}", path, err);
		}
		errors
	}

	/// Apply (create or update) a placeholder at `ns_path`.  The parent
	/// directory must already exist in the backing tmpfs.
	fn apply_placeholder(
		&self,
		ns_path: &CStr,
		placeholder: &ManagedPlaceholder,
	) -> Result<(), BindMountSandboxError> {
		if ns_path == c"/" {
			// Root is the tmpfs itself; no placeholder to manage.
			return Ok(());
		}
		validate_sandbox_path(ns_path)?;
		let (_, leaf) = split_parent_leaf(ns_path);
		let parent_fd = self.sandbox.open_parent_on_placeholder_tmpfs(ns_path)?;
		create_or_update_placeholder(parent_fd.as_raw_fd(), leaf, placeholder)
	}

	/// Build (desired_placeholder_tree, desired_mount_tree) from a
	/// `FsTree<ManagedTreeEntry>`.  For each bind-mount entry, a
	/// placeholder is created at the mount point based on the host path.
	/// Missing ancestor placeholder dirs are automatically added.
	/// Returns the placeholder tree, the mount tree, and any errors
	/// encountered while trying to stat the host paths for bind mounts.
	fn build_desired_trees(
		&self,
		desired_entries: &FsTree<ManagedTreeEntry>,
	) -> (
		FsTree<ManagedPlaceholder>,
		FsTree<ManagedMountPoint>,
		Vec<(OsString, BindMountSandboxError)>,
	) {
		let mut placeholders: FsTree<ManagedPlaceholder> = FsTree::new();
		let mut mounts: FsTree<ManagedMountPoint> = FsTree::new();
		let mut errors: Vec<(OsString, BindMountSandboxError)> = Vec::new();
		desired_entries.walk_top_down(|path, entry| {
			if path.as_encoded_bytes() == b"/" {
				// Root: never a placeholder.  May be a mount target.
				if let ManagedTreeEntry::BindMount(mp) = entry {
					mounts.insert(path, mp.clone());
				}
				return;
			}
			match entry {
				ManagedTreeEntry::Placeholder(p) => {
					placeholders.insert(path, p.clone());
				}
				ManagedTreeEntry::BindMount(mp) => {
					if placeholders.get(path).is_none() {
						let stat = match stat_host(&mp.host_path) {
							Ok(s) => s,
							Err(e) => {
								errors.push((path.to_owned(), e));
								return;
							}
						};
						let is_dir = stat.st_mode & libc::S_IFMT == libc::S_IFDIR;
						placeholders.insert(path, placeholder_default_no_metadata(is_dir));
					}
					mounts.insert(path, mp.clone());
				}
			}
		});
		placeholders.fill_incomplete_parent(|_| placeholder_default_no_metadata(true));
		(placeholders, mounts, errors)
	}

	/// Capture the kernel `mnt_id` of the mount currently topmost at
	/// `ns_path`, by opening an `O_PATH` handle to it in m1 and running
	/// `statx(STATX_MNT_ID)`.  Returns 0 (and logs) if the capture
	/// fails, since a missing id only degrades the fd-staleness check
	/// for that one entry rather than breaking the mount.
	fn capture_mnt_id(&self, ns_path: &CStr) -> u64 {
		let mut openhow: libc::open_how = unsafe { mem::zeroed() };
		openhow.flags = (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
		openhow.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_IN_ROOT;
		match self.sandbox.open_in_sandbox(ns_path, &openhow) {
			Ok(fd) => match fd.mnt_id() {
				Ok(id) => id,
				Err(e) => {
					warn!("Failed to capture mnt_id for {:?}: {}", ns_path, e);
					0
				}
			},
			Err(e) => {
				warn!(
					"Failed to open {:?} in m1 to capture mnt_id: {}",
					ns_path, e
				);
				0
			}
		}
	}

	/// The attributes a path should fall back to when an entry we tried to
	/// remove is kept (app still holds it).  This is the attrs of the
	/// deepest desired entry that is a proper prefix of `path`, or the safe
	/// default `ro,noexec` when none covers it.
	fn covering_attrs(
		&self,
		desired_mt: &FsTree<ManagedMountPoint>,
		path: &std::ffi::OsStr,
	) -> MountAttributes {
		let mut best: Option<MountAttributes> = None;
		let mut best_len = 0usize;
		desired_mt.walk_top_down(|p, mp| {
			let pb = p.as_encoded_bytes();
			let path_b = path.as_encoded_bytes();
			// `p` must be a proper ancestor of `path`: either "/" or a
			// path that `path` continues with a '/' separator.
			let is_ancestor = if pb == b"/" {
				path_b != b"/"
			} else {
				path_b.len() > pb.len() && path_b.starts_with(pb) && path_b[pb.len()] == b'/'
			};
			if is_ancestor && pb.len() >= best_len {
				best_len = pb.len();
				best = Some(mp.attrs);
			}
		});
		best.unwrap_or_else(MountAttributes::ro)
	}

	/// Of the threads recorded as backing the cwd mount at `target`,
	/// return those that still need it.  A holder is retained iff it is
	/// alive and either currently mid-`chdir`/`fchdir` (in which case the
	/// syscall might not have been processed by the kernel yet) or its
	/// cwd is still `target`; a dead or moved-away holder is removed from
	/// the list.
	fn retained_cwd_holders(
		&self,
		holders: &[Arc<ProcPidFd>],
		target: &OsStr,
	) -> Vec<Arc<ProcPidFd>> {
		let target_bytes = target.as_encoded_bytes();
		let mut out = Vec::new();
		for h in holders {
			match h.is_alive() {
				Ok(false) => continue, // dead -> drop
				Ok(true) => {}
				Err(e) => {
					debug!(
						"retained_cwd_holders: error determining if pidfd to {} is still valid: {}",
						h.tid(),
						e
					);
					out.push(h.clone());
					continue;
				}
			}

			// Check if the thread is in a chdir syscall first before we
			// check its cwd.  Doing it the other way may lead to races.
			if h.in_chdir_syscall().unwrap_or_else(|e| {
				error!(
					"failed to determine if pid {} is in chdir syscall: {}",
					h.tid(),
					e
				);
				false
			}) {
				out.push(h.clone());
				continue;
			}
			// Now we know that the thread is not in a chdir syscall, and
			// would not enter one until we return, because our chdir
			// handler takes the mount tree lock, and we're holding the
			// lock now.
			match h.cwd() {
				Ok(cwd) if cwd.as_encoded_bytes() == target_bytes => out.push(h.clone()),
				Ok(_) => { /* moved away -> drop */ }
				Err(e) => {
					debug!(
						"retained_cwd_holders: read of cwd for pid {} failed: {}",
						h.tid(),
						e
					);
					out.push(h.clone());
				}
			}
		}
		out
	}

	pub fn check_covered<'a>(
		&self,
		path: &CStr,
		need_write: bool,
		need_exec: bool,
	) -> Result<(bool, Option<ManagedMountPoint>), BindMountSandboxError> {
		validate_sandbox_path(path)?;
		match self
			.current_mount_tree
			.lock()
			.expect("current_mount_tree lock poisoned")
			.find(OsStr::from_bytes(path.to_bytes()), |_, _| true)
		{
			None => return Ok((false, None)),
			Some((_, mnt)) => {
				if need_write && mnt.user.attrs.readonly {
					return Ok((false, Some(mnt.user.clone())));
				}
				if need_exec && mnt.user.attrs.noexec {
					return Ok((false, Some(mnt.user.clone())));
				}
				Ok((true, Some(mnt.user.clone())))
			}
		}
	}

	pub fn has_placeholder(&self, path: &CStr) -> Result<bool, BindMountSandboxError> {
		validate_sandbox_path(path)?;
		let pt = self
			.current_placeholder_tree
			.lock()
			.expect("current_placeholder_tree lock poisoned");
		Ok(pt.get(OsStr::from_bytes(path.to_bytes())).is_some())
	}

	/// Return the sandbox path and current user-facing mount point of
	/// every mount under `path`, not including `path` itself.
	pub fn mounts_under(
		&self,
		path: &CStr,
	) -> Result<Vec<(OsString, ManagedMountPoint)>, BindMountSandboxError> {
		validate_sandbox_path(path)?;
		let mt = self
			.current_mount_tree
			.lock()
			.expect("current_mount_tree lock poisoned");
		let mut out = Vec::new();
		mt.walk_subtree_top_down(OsStr::from_bytes(path.to_bytes()), false, |p, m| {
			out.push((p.to_os_string(), m.user.clone()));
		});
		Ok(out)
	}

	pub fn restrict_self(&self) -> Result<(), BindMountSandboxError> {
		self.sandbox.restrict_self()
	}

	pub fn run_command(
		&self,
		cmd: &mut std::process::Command,
	) -> Result<std::process::Child, BindMountSandboxError> {
		self.sandbox.run_command(cmd)
	}

	pub fn root_in_sandbox(&self) -> Result<ForeignFd, BindMountSandboxError> {
		self.sandbox.root_in_sandbox()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::sandbox::mountinfo;

	fn try_new_sandbox() -> Option<ManagedBindMountSandbox> {
		match ManagedBindMountSandbox::new(SandboxOptions::default()) {
			Ok(sandbox) => Some(sandbox),
			Err(error) => {
				eprintln!("skipping privileged managed test: setup failed: {error}");
				None
			}
		}
	}

	fn mountinfo_has_mountpoint(raw: &[u8], mountpoint: &[u8]) -> bool {
		mountinfo::parse_mountinfo(raw)
			.iter()
			.any(|entry| entry.mount_point.as_encoded_bytes() == mountpoint)
	}

	fn mountinfo_root_for(raw: &[u8], mountpoint: &[u8]) -> Option<Vec<u8>> {
		mountinfo::parse_mountinfo(raw)
			.iter()
			.filter(|entry| entry.mount_point.as_encoded_bytes() == mountpoint)
			.last()
			.map(|entry| entry.root.as_bytes().to_vec())
	}

	/// Exercise `unmount_covering`: a parent mount with a child
	/// sub-mount is unmounted while the child's `struct mount` identity is
	/// preserved. Afterwards the parent is gone but the child
	/// is restored on the revealed placeholder layer.
	#[test]
	fn unmount_covering_preserves_child() {
		let Some(msb) = try_new_sandbox() else {
			return;
		};
		msb.sandbox
			.mount_host_into_sandbox_impl(c"/etc", c"/p", MountAttributes::ro(), false, true)
			.expect("mount parent /p");
		msb.sandbox
			.mount_host_into_sandbox_impl(c"/etc", c"/p/ssl", MountAttributes::ro(), false, true)
			.expect("mount child /p/ssl");

		let before = msb.sandbox.read_m1_mountinfo().expect("read mountinfo");
		assert!(
			mountinfo_has_mountpoint(&before, b"/p"),
			"/p should be mounted before unmount_covering"
		);
		assert!(
			mountinfo_has_mountpoint(&before, b"/p/ssl"),
			"/p/ssl should be mounted before unmount_covering"
		);

		let unmounted = msb
			.unmount_covering(c"/p", &[CString::new("/p/ssl").unwrap()])
			.expect("unmount_covering /p");
		assert!(
			unmounted,
			"/p should have been unmounted (nothing holds it)"
		);

		let after = msb
			.sandbox
			.read_m1_mountinfo()
			.expect("read mountinfo after");
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
		let Some(msb) = try_new_sandbox() else {
			return;
		};
		let mountpoint = ManagedMountPoint {
			host_path: CString::new("/etc").unwrap(),
			attrs: MountAttributes::ro(),
		};
		msb.add_or_update_mount(OsStr::new("/p"), mountpoint.clone())
			.expect("add /p");
		msb.add_or_update_mount(OsStr::new("/p/ssl"), mountpoint)
			.expect("add /p/ssl");

		let before = msb.sandbox.read_m1_mountinfo().expect("mountinfo");
		assert!(mountinfo_has_mountpoint(&before, b"/p"), "/p mounted");
		assert!(
			mountinfo_has_mountpoint(&before, b"/p/ssl"),
			"/p/ssl mounted"
		);

		msb.remove_entry(OsStr::new("/p")).expect("remove /p");

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
		let Some(msb) = try_new_sandbox() else {
			return;
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
