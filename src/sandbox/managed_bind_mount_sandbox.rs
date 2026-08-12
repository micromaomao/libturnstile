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

use log::{debug, error, warn};

use crate::{
	BindMountSandboxError,
	access::fs::ForeignFd,
	fstree::FsTree,
	sandbox::{
		SandboxOptions,
		bind_mount_sandbox::BindMountSandbox,
		mount_attributes::MountAttributes,
		placeholders::{
			PlaceholderDirData, PlaceholderFileData, PlaceholderSymlinkData,
			create_or_update_placeholder, join_host_suffix, placeholder_default_no_metadata,
			stat_host,
		},
		utils::{split_parent_leaf, validate_sandbox_path},
	},
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

/// Implements a bind-mount based sandbox that automatically mount and
/// unmounts based on a desired state.
#[derive(Debug)]
pub struct ManagedBindMountSandbox {
	pub(super) sandbox: BindMountSandbox,
	/// The desired policy: the source of truth for what *should* be
	/// mounted.  Mutated by `add_/remove_/update_*` and diffed against the
	/// live state by `reconcile`.  Kept separate from the live trees below
	/// (which reflect what is *actually* mounted) so transient mounts that
	/// are reconciled in but never part of the policy - notably `chdir`
	/// cwd mounts - are naturally cleaned up on a later reconcile
	/// instead of lingering forever.
	current_policy: Mutex<FsTree<ManagedTreeEntry>>,
	current_placeholder_tree: Mutex<FsTree<ManagedPlaceholder>>,
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

	/// Convenience: update a single entry (placeholder or mount) and
	/// reconcile.
	///
	/// Reconciliation may touch other paths (ancestors, shadowed
	/// sub-mounts, previously-tracked entries).  Only an error related to
	/// `path` itself is surfaced to the caller; failures on unrelated
	/// paths are logged by `reconcile` but do not fail this call.
	pub fn add_or_update_entry(
		&self,
		path: &OsStr,
		entry: ManagedTreeEntry,
	) -> Result<(), BindMountSandboxError> {
		debug!("add_or_update_entry: path={:?}, entry={:?}", path, entry);
		Self::check_path_no_nul(path)?;
		let (mut policy, mut pt, mut mt) = self.lock_trees();
		policy.insert(path, entry);
		prune_useless_mounts(&mut policy);
		let errors = self.reconcile(&mut pt, &mut mt, &policy, None);
		Self::error_for_path(errors, path)
	}

	/// Create an ephemeral mount at `target` with attribute `mp` to back
	/// the thread `pidfd`'s cwd, without persisting it to the policy.
	pub(super) fn make_ephemeral_mount_for_cwd(
		&self,
		target: &OsStr,
		mp: ManagedMountPoint,
		pidfd: Arc<ProcPidFd>,
	) -> Result<(), BindMountSandboxError> {
		Self::check_path_no_nul(target)?;
		let (policy, mut pt, mut mt) = self.lock_trees();
		let errors = self.reconcile(
			&mut pt,
			&mut mt,
			&policy,
			Some((target.to_owned(), mp, pidfd)),
		);
		Self::error_for_path(errors, target)
	}

	/// Pick out the reconcile error (if any) that relates to `path`,
	/// discarding errors on unrelated paths.
	fn error_for_path(
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

	pub fn add_or_update_mount(
		&self,
		path: &OsStr,
		mp: ManagedMountPoint,
	) -> Result<(), BindMountSandboxError> {
		debug!("add_or_update_mount: path={:?}, mp={:?}", path, mp);
		self.add_or_update_entry(path, ManagedTreeEntry::BindMount(mp))
	}

	pub fn add_or_update_placeholder(
		&self,
		path: &OsStr,
		ph: ManagedPlaceholder,
	) -> Result<(), BindMountSandboxError> {
		debug!("add_or_update_placeholder: path={:?}, ph={:?}", path, ph);
		self.add_or_update_entry(path, ManagedTreeEntry::Placeholder(ph))
	}

	/// Remove either the placeholder or mount entry at the given path.
	pub fn remove_entry(&self, path: &OsStr) -> Result<(), BindMountSandboxError> {
		Self::check_path_no_nul(path)?;
		let (mut policy, mut pt, mut mt) = self.lock_trees();
		policy.remove(path);
		prune_useless_mounts(&mut policy);
		let errors = self.reconcile(&mut pt, &mut mt, &policy, None);
		Self::error_for_path(errors, path)
	}

	pub fn remove_mount(&self, path: &OsStr) -> Result<(), BindMountSandboxError> {
		self.remove_entry(path)
	}

	pub fn update_from_tree(
		&self,
		desired_tree: &FsTree<ManagedTreeEntry>,
	) -> Result<(), BindMountSandboxError> {
		let (mut policy, mut pt, mut mt) = self.lock_trees();
		*policy = desired_tree.clone();
		prune_useless_mounts(&mut policy);
		let errors = self.reconcile(&mut pt, &mut mt, &policy, None);
		// A bulk update has no single "target" path, so surface the
		// first error encountered (all are logged by `reconcile`).
		match errors.into_iter().next() {
			Some((_, e)) => Err(e),
			None => Ok(()),
		}
	}

	pub fn update_from_list<'a>(
		&self,
		desired_entries: impl IntoIterator<Item = (&'a OsStr, ManagedTreeEntry)>,
	) -> Result<(), BindMountSandboxError> {
		let mut tree = FsTree::new();
		for (path, entry) in desired_entries {
			Self::check_path_no_nul(path)?;
			tree.insert(path, entry);
		}
		self.update_from_tree(&tree)
	}

	pub fn update_mounts_from_tree(
		&self,
		desired_tree: &FsTree<ManagedMountPoint>,
	) -> Result<(), BindMountSandboxError> {
		let mut converted = FsTree::new();
		desired_tree.walk_top_down(|path, mp| {
			converted.insert(path, ManagedTreeEntry::BindMount(mp.clone()));
		});
		self.update_from_tree(&converted)
	}

	pub fn update_mounts_from_list<'a>(
		&self,
		desired_mounts: impl IntoIterator<Item = (&'a OsStr, ManagedMountPoint)>,
	) -> Result<(), BindMountSandboxError> {
		self.update_from_list(
			desired_mounts
				.into_iter()
				.map(|(p, m)| (p, ManagedTreeEntry::BindMount(m))),
		)
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
						match self.sandbox.unmount_covering(&ns_path, &children) {
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
						if let Err(e) = self.sandbox.mount_covering(
							&new.host_path,
							&ns_path,
							new.attrs,
							&children,
						) {
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
		let parent_fd = self.sandbox.open_sandbox_parent(ns_path)?;
		create_or_update_placeholder(parent_fd.as_raw_fd(), leaf, placeholder)
	}

	/// Build (desired_placeholder_tree, desired_mount_tree) from an
	/// entry tree.  For each bind-mount entry, a default placeholder is
	/// synthesized at the mount point if the caller didn't supply one;
	/// missing ancestor directories are then filled in via
	/// `FsTree::fill_incomplete_parent` so creation order naturally
	/// flows parent-before-child.
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
						// Skip (and record) this single entry on a stat
						// failure rather than aborting the whole
						// reconcile: an unrelated mount whose host source
						// has vanished must not block updates to other
						// paths.
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
		match self.sandbox.open_in_m1(ns_path, &openhow) {
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
