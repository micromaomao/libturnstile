use std::{
	borrow::Cow,
	ffi::{CStr, CString},
	io, mem,
	os::{
		fd::{AsRawFd, IntoRawFd},
		unix::process::CommandExt,
	},
};

#[cfg(test)]
use std::thread;

use log::{debug, error, info};

use super::SandboxOptions;

use crate::{
	BindMountSandboxError,
	access::fs::ForeignFd,
	perror,
	sandbox::{
		mount_attributes::{MountAttributes, MountBuilder},
		mount_obj::MountObj,
		namespace::{ManagedNamespaces, send_fd_from_ns},
		placeholders::{
			create_or_update_placeholder, placeholder_default_no_metadata,
			placeholder_default_symlink,
		},
		remove_entry_at,
		utils::{split_parent_leaf, validate_sandbox_path},
	},
	utils::{ENABLE_LOG_IN_FORK, fork_wait},
};

fn restrict_self_impl<F: FnOnce() -> Result<(), std::io::Error>>(
	nsenter_fn: F,
	new_cwd_cstr: Option<&CStr>,
) -> Result<(), std::io::Error> {
	match nsenter_fn() {
		Ok(()) => (),
		Err(e) => {
			if ENABLE_LOG_IN_FORK {
				error!("Failed to enter namespaces: {}", e);
			}
			return Err(e);
		}
	}
	if let Some(new_cwd_cstr) = new_cwd_cstr {
		unsafe {
			let res = libc::chdir(new_cwd_cstr.as_ptr());
			if res != 0 {
				let err = perror!("chdir");
				if ENABLE_LOG_IN_FORK {
					error!("Failed to chdir to {:?}: errno {}", new_cwd_cstr, err);
				}
				return Err(io::Error::from_raw_os_error(err));
			}
		}
	}
	Ok(())
}

/// Implements a basic bind-mount based sandbox.  Consider using
/// [`ManagedBindMountSandbox`](crate::sandbox::ManagedBindMountSandbox)
/// instead, which offer a higher-level API and transparent handling of
/// policy changes.
#[derive(Debug)]
pub struct BindMountSandbox {
	/// fd references to namespaces
	pub(super) namespaces: ManagedNamespaces,
	/// O_PATH fd to the host "/" opened inside m0.  Used as the dirfd
	/// when resolving caller-provided host paths so that the resulting fd
	/// is from m0 and is therefore acceptable to `open_tree()` in m0.
	///
	/// Because all host paths are mounted into the sandbox using
	/// recursive bind, m0 should not mount any additional trees,
	/// otherwise they will be mounted into the sandbox as well either at
	/// mount time or through propagation.
	host_root_fd: ForeignFd,
	/// O_PATH fd to the read-write placeholder tmpfs mounted in m1.
	placeholder_tmpfs: MountObj,
	/// O_PATH fd to the scratch tmpfs mounted in m1.  The scratch is a
	/// separate tmpfs (separate from the placeholder tmpfs) that is first
	/// mounted into m1, and then shadowed by mounting the placeholder
	/// rootfs readonly on top, so the sandboxed app never sees it.  It is
	/// used by [`Self::park_to_scratch`] to temporarily park a mount, in
	/// order to unmount a parent, before moving it back.
	m1_scratch_fd: ForeignFd,
	/// O_PATH fd to the read-only placeholder tmpfs mounted in m1.
	placeholder_tmpfs_ro: MountObj,
}

impl BindMountSandbox {
	pub fn new(options: SandboxOptions) -> Result<Self, BindMountSandboxError> {
		let namespaces = ManagedNamespaces::new(options.disable_userns)?;
		// Store a m0 fd to "/" for easy use later without needing to
		// enter m0 again.
		let host_root_fd = unsafe {
			let nsenter_m0 = namespaces.nsenter_fn(true, true, false, false);
			let raw_fd = send_fd_from_ns(
				nsenter_m0,
				|| {
					let fd = libc::open(
						c"/".as_ptr(),
						libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY,
					);
					if fd < 0 {
						Err(io::Error::last_os_error())
					} else {
						Ok(fd)
					}
				},
				BindMountSandboxError::OpenRootInSandboxFailed,
			)?;
			ForeignFd { local_fd: raw_fd }
		};

		// Enter u0 then m1 directly
		let nsenter_m1 = unsafe { namespaces.nsenter_fn(true, false, true, false) };

		// Create the scratch tmpfs inside m1 and make it m1's root, then
		// capture an O_PATH handle to it.
		let m1_scratch_fd = unsafe {
			let raw_fd = send_fd_from_ns(
				&nsenter_m1,
				|| {
					let scratch = MountObj::new_tmpfs()?;
					scratch.mount(libc::AT_FDCWD, c"/", false)?;
					Ok(scratch.into_raw_fd())
				},
				BindMountSandboxError::SetupScratchFailed,
			)?;
			ForeignFd { local_fd: raw_fd }
		};

		// Create the placeholder tmpfs inside m1 and mount it on "/".
		let placeholder_tmpfs = unsafe {
			let raw_fd = send_fd_from_ns(
				&nsenter_m1,
				|| {
					let placeholder = MountObj::new_tmpfs()?;
					placeholder.mount(libc::AT_FDCWD, c"/", false)?;
					Ok(placeholder.into_raw_fd())
				},
				BindMountSandboxError::SetupPlaceholderTmpfsFailed,
			)?;
			MountObj::new_from_fd(raw_fd)
		};

		// Clone the placeholder as a new ro bind mount, then mount it on
		// "/" again in m1.
		let placeholder_tmpfs_ro = unsafe {
			let raw_fd = send_fd_from_ns(
				&nsenter_m1,
				|| {
					let ro_bind = MountObj::new_bind(
						placeholder_tmpfs.0.as_raw_fd(),
						c"",
						MountAttributes::ro(),
						false,
					)?;
					ro_bind.mount(libc::AT_FDCWD, c"/", false)?;
					Ok(ro_bind.into_raw_fd())
				},
				BindMountSandboxError::SetupPlaceholderTmpfsFailed,
			)?;
			MountObj::new_from_fd(raw_fd)
		};

		Ok(Self {
			namespaces,
			host_root_fd,
			m1_scratch_fd,
			placeholder_tmpfs,
			placeholder_tmpfs_ro,
		})
	}

	/// Create either a file or directory at the given absolute path
	/// within the sandbox's backing tmpfs.  This makes a new empty file
	/// or directory appear within the sandbox, unless the path or any of
	/// its parent directories is already bind-mounted to some other host
	/// path, in which case the new file or directory will not be visible.
	///
	/// If any of the path's parent doesn't exist or is not a directory, a
	/// directory is created in its place (overriding any existing files,
	/// which is sensible since this is a placeholder fs).
	///
	/// This backing tmpfs is readonly from the perspective of the
	/// sandboxed process.
	pub fn create_placeholder_hierarchy(
		&self,
		path: &CStr,
		leaf_is_dir: bool,
	) -> Result<ForeignFd, BindMountSandboxError> {
		validate_sandbox_path(path)?;

		let mut fd = self.placeholder_tmpfs.0.clone();
		let components = path
			.to_bytes()
			.split(|&b| b == b'/')
			.filter(|c| !c.is_empty())
			.collect::<Vec<_>>();
		let len = components.len();
		for (i, comp) in components.into_iter().enumerate() {
			let comp = CString::new(comp).unwrap();
			let is_leaf = i == len - 1;
			let want_dir = !is_leaf || leaf_is_dir;
			let placeholder = placeholder_default_no_metadata(want_dir);
			create_or_update_placeholder(fd.as_raw_fd(), &comp, &placeholder)?;
			let newfd = unsafe {
				let mut openhow: libc::open_how = mem::zeroed();
				openhow.flags = (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
				openhow.resolve = libc::RESOLVE_NO_SYMLINKS;
				if i == 0 {
					openhow.resolve |= libc::RESOLVE_IN_ROOT;
				}
				let raw = libc::syscall(
					libc::SYS_openat2,
					fd.as_raw_fd(),
					comp.as_ptr(),
					&openhow as *const _,
					std::mem::size_of::<libc::open_how>(),
				) as libc::c_int;
				if raw < 0 {
					return Err(BindMountSandboxError::ResolveSandboxPath(
						io::Error::last_os_error(),
					));
				}
				ForeignFd { local_fd: raw }
			};
			fd = newfd;
		}
		Ok(fd)
	}

	/// Create a symlink within the sandbox's backing tmpfs, which will
	/// appear within the sandbox unless the location is already within a
	/// bind-mount.  linkpath must be absolute, but target need not be (as
	/// it usually is, relative paths are interpreted relative to the
	/// symlink's parent directory).
	pub fn create_placeholder_symlink(
		&self,
		linkpath: &CStr,
		target: &CStr,
	) -> Result<(), BindMountSandboxError> {
		validate_sandbox_path(linkpath)?;
		if linkpath.to_bytes() == b"/" {
			return Err(BindMountSandboxError::InvalidSandboxPath(
				"cannot create symlink at root",
				linkpath.to_owned(),
			));
		}
		let (parent, child) = split_parent_leaf(linkpath);
		let parent_fd = self.create_placeholder_hierarchy(&parent, true)?;
		let placeholder = placeholder_default_symlink(target.to_owned());
		create_or_update_placeholder(parent_fd.as_raw_fd(), child, &placeholder)?;
		debug!("Created symlink {:?} -> {:?} in sandbox", linkpath, target);
		Ok(())
	}

	/// Remove the given sandbox path from the backing tmpfs, removing
	/// files within the pointed to directory recursively if it's a
	/// directory.  Nothing is done if the path, or any of its parent
	/// components, doesn't exist.
	pub fn remove_placeholder(&self, path: &CStr) -> Result<(), BindMountSandboxError> {
		validate_sandbox_path(path)?;

		if path.to_bytes() == b"/" {
			return Err(BindMountSandboxError::InvalidSandboxPath(
				"cannot remove root",
				path.to_owned(),
			));
		}
		let (parent_path, leaf) = split_parent_leaf(path);

		let parent_fd = unsafe {
			let mut openhow: libc::open_how = mem::zeroed();
			openhow.flags =
				(libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY) as u64;
			// RESOLVE_IN_ROOT and RESOLVE_NO_XDEV are not technically
			// necessary in our setup, but adding for safety.
			openhow.resolve =
				libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_XDEV;
			let fd = libc::syscall(
				libc::SYS_openat2,
				self.placeholder_tmpfs.0.as_raw_fd(),
				parent_path.as_ptr(),
				&openhow as *const _,
				std::mem::size_of::<libc::open_how>(),
			) as libc::c_int;
			if fd < 0 {
				let err = io::Error::last_os_error();
				if err.kind() == io::ErrorKind::NotFound {
					return Ok(());
				}
				return Err(BindMountSandboxError::ResolveSandboxPath(err));
			}
			ForeignFd { local_fd: fd }
		};

		remove_entry_at(parent_fd.as_raw_fd(), leaf)?;

		debug!("Removed {:?} from sandbox tmpfs", path);
		Ok(())
	}

	/// Resolve `host_path` to an `O_PATH` fd in m0.
	pub(super) fn host_to_m0(
		&self,
		host_path: &CStr,
		follow_host_symlinks: bool,
	) -> Result<ForeignFd, BindMountSandboxError> {
		let mut open_how: libc::open_how = unsafe { std::mem::zeroed() };
		open_how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
		if !follow_host_symlinks {
			open_how.flags |= libc::O_NOFOLLOW as u64;
			open_how.resolve |= libc::RESOLVE_NO_SYMLINKS;
		}
		// openat2 ignores the dirfd when given an absolute path, so we
		// need to remove any leading '/'.
		let with_nul = host_path.to_bytes_with_nul();
		let relative_host_path: &CStr = if with_nul.starts_with(b"/") {
			let mut i = 0;
			while i < with_nul.len() - 1 && with_nul[i] == b'/' {
				i += 1;
			}
			if i == with_nul.len() - 1 {
				c"."
			} else {
				CStr::from_bytes_with_nul(&with_nul[i..]).unwrap()
			}
		} else {
			host_path
		};
		let host_fd = unsafe {
			libc::syscall(
				libc::SYS_openat2,
				self.host_root_fd.as_raw_fd(),
				relative_host_path.as_ptr(),
				&open_how,
				std::mem::size_of_val(&open_how),
			) as libc::c_int
		};
		if host_fd < 0 {
			return Err(BindMountSandboxError::ResolveHostPath(
				host_path.to_owned(),
				io::Error::last_os_error(),
			));
		}
		Ok(ForeignFd { local_fd: host_fd })
	}

	// Note: there is no "sandbox-side equivalent" to
	// follow_host_symlinks, since we use create_hierarchy, which has no
	// visibility into bind-mounted symlinks
	pub(super) fn mount_host_into_sandbox_impl(
		&self,
		host_path: &CStr,
		ns_path: &CStr,
		attrs: MountAttributes,
		follow_host_symlinks: bool,
		create_placeholders: bool,
	) -> Result<(), BindMountSandboxError> {
		validate_sandbox_path(ns_path)?;
		let host_fd = self.host_to_m0(host_path, follow_host_symlinks)?;

		if create_placeholders {
			let mut stat: libc::stat = unsafe { std::mem::zeroed() };
			if unsafe { libc::fstat(host_fd.as_raw_fd(), &mut stat) } != 0 {
				return Err(BindMountSandboxError::StatHostPath(
					host_path.to_owned(),
					io::Error::last_os_error(),
				));
			}
			self.create_placeholder_hierarchy(
				ns_path,
				stat.st_mode & libc::S_IFMT == libc::S_IFDIR,
			)?;
		}

		let nsenter_fn_m0 = unsafe { self.namespaces.nsenter_fn(true, true, false, false) };
		let nsenter_fn_m1 = unsafe { self.namespaces.nsenter_fn(false, false, true, false) };
		let host_fd_raw = host_fd.as_raw_fd();
		let fork_res = unsafe {
			fork_wait(|| {
				match nsenter_fn_m0() {
					Ok(()) => (),
					Err(e) => {
						if ENABLE_LOG_IN_FORK {
							error!("Failed to enter namespaces: {}", e);
						}
						return e.raw_os_error().unwrap_or(libc::EIO);
					}
				}
				// host_fd was opened relative to host_root_fd (which was
				// opened inside m0), so it carries m0's mount namespace
				// context and is acceptable to open_tree() here without
				// needing to be reopened.
				let source_tree =
					match MountObj::new_bind(host_fd_raw, c"", attrs, follow_host_symlinks) {
						Ok(tree) => tree,
						Err(e) => {
							return e.raw_os_error().unwrap_or(libc::EIO);
						}
					};
				match nsenter_fn_m1() {
					Ok(()) => (),
					Err(e) => {
						if ENABLE_LOG_IN_FORK {
							error!("Failed to enter namespaces: {}", e);
						}
						return e.raw_os_error().unwrap_or(libc::EIO);
					}
				}
				match source_tree.mount(libc::AT_FDCWD, ns_path, false) {
					Ok(()) => (),
					Err(e) => {
						return e.raw_os_error().unwrap_or(libc::EIO);
					}
				}
				0
			})
		}
		.map_err(BindMountSandboxError::ForkError)?;
		if fork_res != 0 {
			error!(
				"Failed to bind mount {:?} to {:?} with {}: errno {}",
				host_path, ns_path, attrs, fork_res
			);
			return Err(BindMountSandboxError::MountFailed(fork_res));
		}
		info!("Mount bind {:?} {:?} {}", host_path, ns_path, attrs,);
		Ok(())
	}

	/// Open the parent directory of `sandbox_path` within the placeholder
	/// tmpfs, without creating any intermediate components.  The parent
	/// must already exist.
	pub(super) fn open_parent_on_placeholder_tmpfs(
		&self,
		sandbox_path: &CStr,
	) -> Result<ForeignFd, BindMountSandboxError> {
		let (parent, _) = split_parent_leaf(sandbox_path);
		if parent.as_c_str() == c"/" {
			let dup = unsafe {
				libc::fcntl(
					self.placeholder_tmpfs.0.as_raw_fd(),
					libc::F_DUPFD_CLOEXEC,
					0,
				)
			};
			if dup < 0 {
				return Err(BindMountSandboxError::ResolveSandboxPath(
					io::Error::last_os_error(),
				));
			}
			return Ok(ForeignFd { local_fd: dup });
		}
		unsafe {
			let mut openhow: libc::open_how = mem::zeroed();
			openhow.flags =
				(libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY) as u64;
			openhow.resolve =
				libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_XDEV;
			let fd = libc::syscall(
				libc::SYS_openat2,
				self.placeholder_tmpfs.0.as_raw_fd(),
				parent.as_ptr(),
				&openhow as *const _,
				std::mem::size_of::<libc::open_how>(),
			) as libc::c_int;
			if fd < 0 {
				return Err(BindMountSandboxError::ResolveSandboxPath(
					io::Error::last_os_error(),
				));
			}
			Ok(ForeignFd { local_fd: fd })
		}
	}

	/// Bind mount a host path onto the given sandbox path within the sandbox.
	pub fn mount_host_into_sandbox<'a, 'b>(
		&'b self,
		host_path: &'a CStr,
		sandbox_path: &'a CStr,
	) -> MountBuilder<'a, 'b> {
		MountBuilder {
			host_path,
			sandbox_path,
			attrs: MountAttributes::default(),
			follow_host_symlinks: false,
			// follow_sandbox_symlinks: false,
			sandbox: self,
		}
	}

	/// Unmount a bind mount at the given sandbox path.  The path must
	/// have been previously bind-mounted with
	/// [`Self::mount_host_into_sandbox`].
	///
	/// If `mnt_detach` is true, umount is called with `MNT_DETACH`.  This
	/// will break ".." on any existing handles to within the mount.
	pub fn unmount(
		&self,
		sandbox_path: &CStr,
		mnt_detach: bool,
	) -> Result<(), BindMountSandboxError> {
		validate_sandbox_path(sandbox_path)?;
		let (parent_path, leaf) = split_parent_leaf(sandbox_path);
		let is_root = sandbox_path == c"/";
		let leaf = if is_root { c"/.." } else { leaf }; // See comment below

		debug!(
			"Umounting {:?} from sandbox (mnt_detach = {})",
			sandbox_path, mnt_detach
		);

		let nsenter_fn = unsafe { self.namespaces.nsenter_fn(true, true, true, false) };
		let fork_res = unsafe {
			fork_wait(|| {
				match nsenter_fn() {
					Ok(()) => (),
					Err(e) => {
						if ENABLE_LOG_IN_FORK {
							error!("Failed to enter namespaces: {}", e);
						}
						return e.raw_os_error().unwrap_or(libc::EIO);
					}
				}
				let mut openhow: libc::open_how = mem::zeroed();
				openhow.flags = (libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY) as u64;
				openhow.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_IN_ROOT;
				if !is_root {
					let parent_fd = libc::syscall(
						libc::SYS_openat2,
						libc::AT_FDCWD,
						parent_path.as_ptr(),
						&openhow as *const _,
						std::mem::size_of::<libc::open_how>(),
					) as libc::c_int;
					if parent_fd < 0 {
						return perror!("openat2(parent)");
					}
					let res = libc::fchdir(parent_fd);
					libc::close(parent_fd);
					if res != 0 {
						return perror!("fchdir");
					}
				} else {
					// In order to unmount the "/" of the sandbox (for
					// example, if a previous mount_host_into_sandbox call
					// mounted something onto "/"), we cannot be within
					// that "/".  Therefore, we chdir and chroot into the
					// placeholder tmpfs ro bind, which will be below
					// whatever's currently mounted above it, then use
					// ".." (see follow_dotdot() and step_into()) to
					// acquire the current "/".
					if libc::fchdir(self.placeholder_tmpfs_ro.0.as_raw_fd()) != 0 {
						return perror!("fchdir(placeholder root)");
					}
					if libc::chroot(c".".as_ptr()) != 0 {
						return perror!("chroot(placeholder root)");
					}
				}
				let mut flags = libc::UMOUNT_NOFOLLOW;
				if mnt_detach {
					flags |= libc::MNT_DETACH;
				}
				let res = libc::umount2(leaf.as_ptr(), flags);
				if res != 0 {
					return perror!("umount2");
				}
				0
			})
		}
		.map_err(BindMountSandboxError::ForkError)?;
		if fork_res != 0 {
			if fork_res != libc::EBUSY {
				error!("Failed to unmount {:?}: errno {}", sandbox_path, fork_res);
			}
			return Err(BindMountSandboxError::UnmountFailed(fork_res));
		} else {
			info!("Unmounted {:?}", sandbox_path);
		}
		Ok(())
	}

	/// Update the attributes of an existing mount within the sandbox.
	/// Symlinks are not followed.  Caller should store and pass in the
	/// existing attributes to avoid EPERM errors caused by trying to
	/// clear attributes that we didn't previously set (and thus have no
	/// rights to clear).
	pub fn set_mount_attr(
		&self,
		ns_path: &CStr,
		attrs: MountAttributes,
		existing_attrs: MountAttributes,
	) -> Result<(), BindMountSandboxError> {
		validate_sandbox_path(ns_path)?;
		let nsenter_fn = unsafe { self.namespaces.nsenter_fn(true, true, true, false) };
		let fork_res = unsafe {
			fork_wait(|| {
				match nsenter_fn() {
					Ok(()) => (),
					Err(e) => {
						if ENABLE_LOG_IN_FORK {
							error!("Failed to enter namespaces: {}", e);
						}
						return e.raw_os_error().unwrap_or(libc::EIO);
					}
				}
				let mut openhow: libc::open_how = mem::zeroed();
				openhow.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
				openhow.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_IN_ROOT;
				let fd = libc::syscall(
					libc::SYS_openat2,
					libc::AT_FDCWD,
					ns_path.as_ptr(),
					&openhow,
					std::mem::size_of_val(&openhow),
				) as libc::c_int;
				if fd < 0 {
					return perror!("open");
				}
				let mnt = MountObj::new_from_fd(fd);
				match mnt.setattr(attrs, existing_attrs, 0) {
					Ok(()) => 0,
					Err(e) => e.raw_os_error().unwrap_or(libc::EIO),
				}
			})
		}
		.map_err(BindMountSandboxError::ForkError)?;
		if fork_res != 0 {
			error!(
				"Failed to set mount attributes for {:?} to {}: errno {}",
				ns_path, attrs, fork_res
			);
			return Err(BindMountSandboxError::MountSetAttrsFailed(fork_res));
		} else {
			info!("Set mount attributes for {:?} to {}", ns_path, attrs);
		}
		Ok(())
	}

	/// Open the absolute `path` inside m1 and u1, resolving through the
	/// sandbox's mount layout.
	pub(super) fn open_in_m1(
		&self,
		path: &CStr,
		openhow: &libc::open_how,
	) -> Result<ForeignFd, BindMountSandboxError> {
		let raw_fd = unsafe {
			let nsenter_fn = self.namespaces.nsenter_fn(true, false, true, true);
			send_fd_from_ns(
				nsenter_fn,
				|| {
					let fd = libc::syscall(
						libc::SYS_openat2,
						libc::AT_FDCWD,
						path.as_ptr(),
						openhow,
						std::mem::size_of::<libc::open_how>(),
					) as libc::c_int;
					if fd < 0 {
						return Err(io::Error::last_os_error());
					}
					Ok(fd)
				},
				BindMountSandboxError::OpenInM1Failed,
			)?
		};
		Ok(ForeignFd { local_fd: raw_fd })
	}

	/// Read `/proc/self/mountinfo` as seen from inside m1, returning its
	/// raw bytes.  A short-lived helper forks, `setns`es into m1, reads
	/// its own mountinfo (now m1's view) and streams it back.  Used by the
	/// integration tests to introspect the live mount layout.
	#[cfg(test)]
	pub(super) fn read_m1_mountinfo(&self) -> Result<Vec<u8>, BindMountSandboxError> {
		let nsenter_fn = unsafe { self.namespaces.nsenter_fn(true, false, true, false) };
		unsafe {
			thread::scope(|s| {
				let mut pipe_fds = [-1i32; 2];
				if libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
					return Err(BindMountSandboxError::ReadMountinfoFailed(
						io::Error::last_os_error(),
					));
				}
				let read_fd = pipe_fds[0];
				let write_fd = pipe_fds[1];

				// Read the whole pipe concurrently with the child writing,
				// so a mountinfo larger than the pipe buffer can't
				// deadlock.
				let reader = s.spawn(move || {
					let mut out = Vec::new();
					let mut buf = [0u8; 8192];
					loop {
						let n =
							libc::read(read_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
						if n < 0 {
							let err = io::Error::last_os_error();
							if err.kind() == io::ErrorKind::Interrupted {
								continue;
							}
							libc::close(read_fd);
							return Err(err);
						}
						if n == 0 {
							break;
						}
						out.extend_from_slice(&buf[..n as usize]);
					}
					libc::close(read_fd);
					Ok(out)
				});

				let fork_res = fork_wait(|| {
					libc::close(read_fd);
					// Pin a handle to the host procfs *before* entering m1,
					// because m1's mount layout has no /proc mounted.  An
					// fd to procfs stays valid across setns; reading
					// `self/mountinfo` through it still reflects the
					// reader's *current* mount namespace (m1 after setns),
					// rendered relative to m1's root (mntns_install sets
					// our fs root/pwd to m1's root).
					let proc_fd = libc::open(
						c"/proc".as_ptr(),
						libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
					);
					if proc_fd < 0 {
						return perror!("open(/proc)");
					}
					match nsenter_fn() {
						Ok(()) => (),
						Err(e) => {
							if ENABLE_LOG_IN_FORK {
								error!("Failed to enter m1 for mountinfo: {}", e);
							}
							libc::close(proc_fd);
							return e.raw_os_error().unwrap_or(libc::EIO);
						}
					}
					let src = libc::openat(
						proc_fd,
						c"self/mountinfo".as_ptr(),
						libc::O_RDONLY | libc::O_CLOEXEC,
					);
					libc::close(proc_fd);
					if src < 0 {
						return perror!("openat(/proc/self/mountinfo)");
					}
					let mut buf = [0u8; 8192];
					loop {
						let n = libc::read(src, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
						if n < 0 {
							let err = libc::__errno_location().read();
							if err == libc::EINTR {
								continue;
							}
							libc::close(src);
							return err;
						}
						if n == 0 {
							break;
						}
						let mut off = 0isize;
						while off < n {
							let w = libc::write(
								write_fd,
								buf.as_ptr().offset(off) as *const libc::c_void,
								(n - off) as usize,
							);
							if w < 0 {
								let err = libc::__errno_location().read();
								if err == libc::EINTR {
									continue;
								}
								libc::close(src);
								return err;
							}
							off += w;
						}
					}
					libc::close(src);
					0
				});
				// Closing our copy of the write end lets the reader see EOF.
				libc::close(write_fd);

				let fork_res = match fork_res {
					Ok(c) => c,
					Err(e) => {
						let _ = reader.join();
						return Err(BindMountSandboxError::ForkError(e));
					}
				};
				let read_res = reader.join().expect("mountinfo reader thread panicked");
				if fork_res != 0 {
					return Err(BindMountSandboxError::ReadMountinfoFailed(
						io::Error::from_raw_os_error(fork_res),
					));
				}
				read_res.map_err(BindMountSandboxError::ReadMountinfoFailed)
			})
		}
	}

	/// Move the mount currently at `ns_path` into the hidden scratch
	/// tmpfs at `scratch/<name>`.  This is used to temporarily "park" a
	/// child mount out of the way when we want to unmount the parent
	/// while preserving the child.
	pub(super) fn park_to_scratch(
		&self,
		ns_path: &CStr,
		name: &CStr,
	) -> Result<(), BindMountSandboxError> {
		validate_sandbox_path(ns_path)?;
		let scratch_fd = self.m1_scratch_fd.as_raw_fd();
		let nsenter_fn = unsafe { self.namespaces.nsenter_fn(true, true, true, false) };
		let fork_res = unsafe {
			fork_wait(|| {
				match nsenter_fn() {
					Ok(()) => (),
					Err(e) => return e.raw_os_error().unwrap_or(libc::EIO),
				}
				// Create scratch/<name> to receive the parked mount.
				if libc::mkdirat(scratch_fd, name.as_ptr(), 0o700) != 0 {
					let err = libc::__errno_location().read();
					if err != libc::EEXIST {
						return perror!("mkdirat(scratch/name)");
					}
				}
				let mut openhow: libc::open_how = mem::zeroed();
				openhow.flags = (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
				openhow.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_IN_ROOT;
				let src_fd = libc::syscall(
					libc::SYS_openat2,
					libc::AT_FDCWD,
					ns_path.as_ptr(),
					&openhow as *const _,
					std::mem::size_of::<libc::open_how>(),
				) as libc::c_int;
				if src_fd < 0 {
					return perror!("openat2(park source)");
				}
				let res = libc::syscall(
					libc::SYS_move_mount,
					src_fd,
					c"".as_ptr(),
					scratch_fd,
					name.as_ptr(),
					libc::MOVE_MOUNT_F_EMPTY_PATH,
				);
				libc::close(src_fd);
				if res != 0 {
					return perror!("move_mount(park)");
				}
				0
			})
		}
		.map_err(BindMountSandboxError::ForkError)?;
		if fork_res != 0 {
			return Err(BindMountSandboxError::ParkToScratchFailed(fork_res));
		}
		Ok(())
	}

	/// Move a previously parked mount at `scratch/<name>` back to
	/// `dest` (an absolute m1 path whose mountpoint dentry must exist),
	/// then remove the now-empty `scratch/<name>` directory.  The inverse
	/// of [`Self::park_to_scratch`].
	pub(super) fn restore_from_scratch(
		&self,
		name: &CStr,
		dest: &CStr,
	) -> Result<(), BindMountSandboxError> {
		validate_sandbox_path(dest)?;
		let scratch_fd = self.m1_scratch_fd.as_raw_fd();
		let nsenter_fn = unsafe { self.namespaces.nsenter_fn(true, true, true, false) };
		let fork_res = unsafe {
			fork_wait(|| {
				match nsenter_fn() {
					Ok(()) => (),
					Err(e) => return e.raw_os_error().unwrap_or(libc::EIO),
				}
				let mut openhow: libc::open_how = mem::zeroed();
				openhow.flags = (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
				openhow.resolve = libc::RESOLVE_NO_SYMLINKS;
				let src_fd = libc::syscall(
					libc::SYS_openat2,
					scratch_fd,
					name.as_ptr(),
					&openhow as *const _,
					std::mem::size_of::<libc::open_how>(),
				) as libc::c_int;
				if src_fd < 0 {
					return perror!("openat2(scratch/name)");
				}
				let mut dest_openhow: libc::open_how = mem::zeroed();
				dest_openhow.flags = (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
				dest_openhow.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_IN_ROOT;
				let dest_fd = libc::syscall(
					libc::SYS_openat2,
					libc::AT_FDCWD,
					dest.as_ptr(),
					&dest_openhow as *const _,
					std::mem::size_of::<libc::open_how>(),
				) as libc::c_int;
				if dest_fd < 0 {
					libc::close(src_fd);
					return perror!("openat2(restore dest)");
				}
				let res = libc::syscall(
					libc::SYS_move_mount,
					src_fd,
					c"".as_ptr(),
					dest_fd,
					c"".as_ptr(),
					libc::MOVE_MOUNT_F_EMPTY_PATH | libc::MOVE_MOUNT_T_EMPTY_PATH,
				);
				libc::close(src_fd);
				libc::close(dest_fd);
				if res != 0 {
					return perror!("move_mount(restore)");
				}
				// Best-effort cleanup of the now-empty scratch dir.
				libc::unlinkat(scratch_fd, name.as_ptr(), libc::AT_REMOVEDIR);
				0
			})
		}
		.map_err(BindMountSandboxError::ForkError)?;
		if fork_res != 0 {
			return Err(BindMountSandboxError::RestoreFromScratchFailed(fork_res));
		}
		Ok(())
	}

	/// instead of [`Self::run_command`], most likely within a pre_exec
	/// hook or after fork()ing.  This cannot be used if the current
	/// process contains more than one threads.
	pub fn restrict_self(&self) -> Result<(), BindMountSandboxError> {
		let nsenter_fn = unsafe { self.namespaces.nsenter_fn(true, true, true, true) };
		// TODO: getcwd, then translate into sandbox path
		restrict_self_impl(nsenter_fn, None).map_err(BindMountSandboxError::RestrictSelf)
	}

	/// Run a command within the sandbox.  Can be called more than once
	/// (unlike
	/// [`TurnstileTracer::run_command`](crate::tracer::TurnstileTracer::run_command))
	pub fn run_command(
		&self,
		cmd: &mut std::process::Command,
	) -> Result<std::process::Child, BindMountSandboxError> {
		let new_cwd = match cmd.get_current_dir() {
			Some(path) => Cow::Borrowed(path),
			None => Cow::Owned(std::env::current_dir().map_err(BindMountSandboxError::Getcwd)?),
		};
		let new_cwd_cstr = std::ffi::CString::new(new_cwd.as_os_str().as_encoded_bytes())
			.expect("current directory path contains NUL byte");
		// todo: translate new_cwd_cstr into sandbox path
		self.create_placeholder_hierarchy(&new_cwd_cstr, true)?;
		unsafe {
			let nsenter_fn = self.namespaces.nsenter_fn(true, true, true, true);
			cmd.pre_exec(move || restrict_self_impl(&nsenter_fn, Some(&new_cwd_cstr)))
		};
		let child = cmd.spawn().map_err(BindMountSandboxError::Spawn)?;
		Ok(child)
	}

	pub fn root_in_sandbox(&self) -> Result<ForeignFd, BindMountSandboxError> {
		unsafe {
			let nsenter_fn = self.namespaces.nsenter_fn(true, true, true, true);
			Ok(ForeignFd {
				local_fd: send_fd_from_ns(
					nsenter_fn,
					|| {
						let fd = libc::open(
							c"/".as_ptr(),
							libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
						);
						if fd < 0 {
							let err = perror!("Failed to open root in sandbox namespace");
							return Err(io::Error::from_raw_os_error(err));
						}
						Ok(fd)
					},
					BindMountSandboxError::OpenRootInSandboxFailed,
				)?,
			})
		}
	}
}
